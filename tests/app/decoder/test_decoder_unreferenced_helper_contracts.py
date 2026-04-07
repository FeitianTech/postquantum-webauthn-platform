from __future__ import annotations

import base64
import hashlib

import cbor2
import pytest
from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData


def _auth_data_bytes() -> bytes:
    credential_id = b"decoder-unreferenced"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        4,
        credential_data,
    )
    return bytes(auth_data)


def _attestation_object_bytes() -> bytes:
    auth_data = AuthenticatorData(_auth_data_bytes())
    return bytes(AttestationObject.create("none", auth_data, {}))


def test_ctap_label_key_and_map_building_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._resolve_ctap_label({1: "one", "2": "two"}, 1) == "one"
    assert decode_module._resolve_ctap_label({1: "one", "2": "two"}, 2) == "two"
    assert decode_module._resolve_ctap_label({1: "one"}, 99) is None

    assert decode_module._format_ctap_entry_key(b"\xaa", "blob") == "aa (blob)"
    assert decode_module._format_ctap_entry_key(7, None) == "7"

    built = decode_module._build_labeled_ctap_map(
        {1: b"\x01", 2: {"x": 1}, "unknown": b"\xff"},
        {1: "clientDataHash", 2: "rp", 3: "missingKey"},
        {"clientDataHash": decode_module._convert_optional_ctap_field},
        missing_keys=(3,),
    )
    assert "1 (clientDataHash)" in built
    assert built["1 (clientDataHash)"] == "01"
    assert "3 (missingKey)" in built


def test_ctap_shape_detection_and_classification_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    client_data_hash = b"\x11" * 32
    auth_data = _auth_data_bytes()

    make_request = {1: client_data_hash, 2: {"id": "example.com"}, 3: {"id": b"u"}}
    get_request = {1: "example.com", 2: client_data_hash}
    make_output = {1: "packed", 2: auth_data, 3: {"alg": -7, "sig": b"\xaa"}}
    get_output = {1: {"id": b"id"}, 2: auth_data, 3: b"\xaa" * 32}

    assert decode_module._looks_like_make_credential_request(make_request) is True
    assert decode_module._looks_like_get_assertion_request(get_request) is True
    assert decode_module._looks_like_make_credential_output(make_output) is True
    assert decode_module._looks_like_get_assertion_output(get_output) is True

    assert decode_module._classify_ctap_map(make_output) == "make_credential_output"
    assert decode_module._classify_ctap_map(get_output) == "get_assertion_output"
    assert decode_module._classify_ctap_map(make_request) == "make_credential_input"
    assert decode_module._classify_ctap_map(get_request) == "get_assertion_input"


def test_ctap_field_converters_and_auth_data_format_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_data_bytes()

    allow_list = decode_module._convert_ctap_allow_list(
        [{"type": "public-key", "id": b"\x01\x02"}]
    )
    assert allow_list[0]["id"] == "0102"

    pub_key_params = decode_module._convert_pub_key_cred_params(
        [{"alg": -7, "type": "public-key"}]
    )
    assert pub_key_params[0]["alg"] == -7

    auth_field = decode_module._convert_auth_data_field(auth_data)
    assert auth_field["signCount"] == 4
    assert auth_field["rpIdHash"]

    assert decode_module._convert_signature_field(b"\xaa\xbb") == "aabb"
    assert decode_module._convert_signature_field(None) is None

    att_stmt = decode_module._convert_att_stmt_field({"sig": b"\xaa", "alg": -7})
    assert att_stmt["sig"] == "aa"
    assert att_stmt["alg"] == -7

    user_value = decode_module._convert_ctap_user_field({1: b"\x99", 2: b"alice"})
    assert user_value["id"] == "99"


def test_trailing_map_and_signature_extraction_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    signature = b"S" * 32
    raw_trailing = (
        cbor2.dumps(3)
        + cbor2.dumps(signature)
        + cbor2.dumps(4)
        + cbor2.dumps({"id": "user"})
    )

    decoded_map = decode_module._decode_trailing_map(raw_trailing)
    assert decoded_map[3] == signature
    assert decoded_map[4]["id"] == "user"

    map_entries = decode_module._extract_lenient_map_entries(cbor2.dumps({1: 2, 3: 4}))
    assert map_entries == [(1, 2), (3, 4)]

    extracted_signature = decode_module._extract_signature_from_raw_bytes(raw_trailing)
    assert extracted_signature == signature


def test_expanded_ctap_json_builder_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    client_data_hash = b"\x22" * 32
    auth_data = _auth_data_bytes()

    make_request = {
        1: client_data_hash,
        2: {"id": "example.com", "name": "Example"},
        3: {1: b"\x01", 2: b"alice"},
        4: [{"type": "public-key", "alg": -7}],
    }
    get_request = {1: "example.com", 2: client_data_hash, 3: [{"id": b"\x01"}]}

    make_response = {1: "packed", 2: auth_data, 3: {"alg": -7, "sig": b"\xaa"}}
    get_response = {1: {"id": b"\x01"}, 2: auth_data}

    make_request_expanded = decode_module._build_make_credential_request_expanded_json(make_request)
    get_request_expanded = decode_module._build_get_assertion_request_expanded_json(get_request)
    make_response_expanded = decode_module._build_make_credential_expanded_json(make_response)

    assert any("clientDataHash" in key for key in make_request_expanded)
    assert any("rpId" in key for key in get_request_expanded)
    assert any("attStmt" in key for key in make_response_expanded)

    trailing_signature = (
        cbor2.dumps(3)
        + cbor2.dumps(b"T" * 32)
        + cbor2.dumps(4)
        + cbor2.dumps({"id": "u"})
    )
    get_response_expanded = decode_module._build_get_assertion_expanded_json(
        get_response,
        raw_bytes=trailing_signature,
    )
    signature_key = next(k for k in get_response_expanded if "signature" in k)
    assert get_response_expanded[signature_key] == (b"T" * 32).hex()


def test_result_conversion_helpers_for_all_base_payload_types(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "_build_credential_overview", lambda _d: {"id": "cred"}, raising=False)
    monkeypatch.setattr(decode_module, "_convert_attestation_entry", lambda _e: {"fmt": "none"}, raising=False)
    monkeypatch.setattr(decode_module, "_build_authenticator_section", lambda *_a, **_k: {"counter": 1}, raising=False)
    monkeypatch.setattr(decode_module, "_convert_client_data_entry", lambda _e: {"type": "webauthn.create"}, raising=False)
    monkeypatch.setattr(decode_module, "_collect_response_extras", lambda _e: {"signature": "aa"}, raising=False)

    pk_data = decode_module._convert_public_key_credential_data(
        {"decoded": {"response": {}, "clientExtensionResults": {"credProps": {"rk": True}}}}
    )
    assert pk_data["credential"]["id"] == "cred"
    assert pk_data["attestationObject"]["fmt"] == "none"
    assert pk_data["authenticatorData"]["counter"] == 1
    assert pk_data["clientDataJSON"]["type"] == "webauthn.create"
    assert pk_data["responseDetails"]["signature"] == "aa"

    monkeypatch.setattr(decode_module, "_extract_authenticator_bytes_from_attestation", lambda _e: b"\x00" * 37, raising=False)
    monkeypatch.setattr(decode_module, "_build_authenticator_data_payload", lambda *_a, **_k: {"flags": {"UP": True}}, raising=False)
    att_obj_data = decode_module._convert_attestation_object_data(
        {"decoded": {"extensions": {"credProps": {"rk": True}}}, "binary": {"base64": "AQI="}}
    )
    assert att_obj_data["attestationObject"]["fmt"] == "none"
    assert att_obj_data["authenticatorData"]["flags"]["UP"] is True
    assert att_obj_data["extensions"]["credProps"]["rk"] is True

    auth_result = decode_module._convert_authenticator_data_result(
        {"decoded": {}, "binary": {"hex": "00" * 37}}
    )
    assert auth_result["flags"]["UP"] is True

    client_result = decode_module._convert_client_data_result({"decoded": {"type": "webauthn.get"}})
    assert client_result["type"] == "webauthn.create"

    cert_result = decode_module._convert_certificate_result(
        {"decoded": {"certificates": [{"derBase64": "AQI=", "pem": "PEM"}]}}
    )
    assert cert_result["certificates"][0]["parsedX5c"]["derBase64"] == "AQI="


def test_summary_and_extension_helpers_for_rendering_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = []
    decode_module._append_simple_field(lines, "Field", None)
    decode_module._append_multiline_field(lines, "Block", ["line-1", "line-2"], indent_str="  ")
    assert "Field:\t(none)" in lines
    assert "Block:\t" in lines

    assert decode_module._format_boolean(True) == "true"
    assert decode_module._format_boolean("False") == "false"
    assert decode_module._format_counter_value(10) == "0x0000000a=10"
    assert decode_module._format_counter_value(-1) == "-1"

    flag_line = decode_module._format_flag_line(
        {
            "value": 0x45,
            "bitfield": "0b01000101",
            "userPresent": True,
            "userVerified": True,
            "backupEligibility": False,
            "backupState": False,
            "attestedCredentialDataIncluded": True,
            "extensionDataIncluded": False,
        }
    )
    assert flag_line.startswith("0x45=")

    auth_bytes = _auth_data_bytes()
    assert decode_module._build_authenticator_data_lines(auth_bytes, None)
    assert decode_module._parse_attested_data(auth_bytes)

    assert decode_module._resolve_cose_algorithm({3: -7}) == "ES256"
    converted_cose = decode_module._convert_cose_key_for_display({-2: base64.urlsafe_b64encode(b"abc").decode("ascii")})
    assert converted_cose[-2] == "616263"

    assert decode_module._decode_base64_field("YWJj") == b"abc"
    assert decode_module._decode_base64_field("%%%") is None

    assert decode_module._extract_hex_from_binary({"hex": "aabb"}) == "aabb"
    extracted_auth = decode_module._extract_authenticator_bytes({"authenticatorData": {"hex": "00" * 37}})
    assert extracted_auth == b"\x00" * 37

    lines = []
    decode_module._extend_with_authenticator_extensions(lines, {"extensions": {"summary": {"rk": True}}})
    decode_module._extend_with_client_extensions(lines, {"credProps": {"rk": True}})
    decode_module._extend_with_client_data_entry(lines, {"details": {"type": "webauthn.get", "challenge": "AQID", "origin": "https://example.com", "crossOrigin": False}})
    assert any("Authenticator extensions" in line for line in lines)
    assert any("Client extensions" in line for line in lines)

    monkeypatch.setattr(decode_module, "_extract_authenticator_bytes", lambda *_a, **_k: b"\x00" * 37, raising=False)
    monkeypatch.setattr(decode_module, "_extract_authenticator_bytes_from_attestation", lambda _e: b"\x00" * 37, raising=False)
    monkeypatch.setattr(decode_module, "_build_certificate_summary_lines", lambda _d: ["Certificate line"], raising=False)

    pk_summary = decode_module._format_public_key_credential_summary(
        {
            "format": "PublicKeyCredential",
            "decoded": {
                "response": {
                    "attestationObject": {"raw": base64.b64encode(_attestation_object_bytes()).decode("ascii"), "details": {"attestationFormat": "none"}},
                    "clientDataJSON": {"details": {"type": "webauthn.create", "challenge": "AQID", "origin": "https://example.com", "crossOrigin": False}},
                },
                "clientExtensionResults": {"credProps": {"rk": True}},
            },
        }
    )
    assert any("Detected type:\tPublicKeyCredential" == line for line in pk_summary)

    cert_summary = decode_module._format_certificate_summary(
        {"format": "X.509 certificate", "decoded": {"subject": "CN=Demo"}}
    )
    assert any("Detected type:\tX.509 certificate" == line for line in cert_summary)

    json_summary = decode_module._format_json_summary({"decoded": {"a": 1}})
    assert any("Detected type:\tJSON" == line for line in json_summary)

    cbor_summary = decode_module._format_cbor_summary(
        {
            "decoded": {
                "ctap": {"meaning": "AuthenticatorGetAssertion command", "codeHex": "0x02", "kind": "command", "payloadLength": 12},
                "ctapDecoded": {"getAssertionResponse": {"signature": "aa"}},
                "expandedJson": {"signature": "aa"},
                "decodedValue": {"k": "v"},
            }
        }
    )
    assert any("Detected type:\tCBOR (AuthenticatorGetAssertion command)" == line for line in cbor_summary)

    generic_summary = decode_module._format_generic_summary({"format": None, "decoded": {"x": 1}})
    assert any("Detected type:\tDecoded data" == line for line in generic_summary)
