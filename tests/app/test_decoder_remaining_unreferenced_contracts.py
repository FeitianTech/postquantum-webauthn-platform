from __future__ import annotations

import math

import cbor2
import pytest
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData


def _auth_data_bytes() -> bytes:
    credential_id = b"decoder-remaining"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        b"\x11" * 32,
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        3,
        credential_data,
    )
    return bytes(auth_data)


def test_remaining_cbor_key_float_and_lenient_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._key_variant_identity(b"x") == ("bytes", b"x")
    assert decode_module._key_variant_identity(7) == ("other", 7)

    assert decode_module._float_summary(float("inf")) == "float(+Infinity)"
    assert decode_module._float_summary(float("-inf")) == "float(-Infinity)"
    assert decode_module._float_summary(float("nan")) == "float(NaN)"
    assert decode_module._float_summary(1.5) == "float(1.5)"

    structure, offset = decode_module._decode_cbor_structure(cbor2.dumps({1: 2}))
    assert structure["type"] == "map"
    assert offset > 0

    assert decode_module._lenient_read_uint(24, b"\x7f", 0) == (0x7F, 1)
    assert decode_module._lenient_read_uint(25, b"\x00", 0) == (0, 1)

    raw = cbor2.dumps(3) + cbor2.dumps(b"S" * 32) + cbor2.dumps(4) + cbor2.dumps({"id": "user"})
    signature_start = raw.find(b"S")
    trailing_offset = decode_module._locate_get_assertion_trailing_offset(raw, signature_start)
    assert trailing_offset >= signature_start

    assert decode_module._derive_alg_from_auth_data(None) is None
    assert decode_module._derive_alg_from_auth_data(_auth_data_bytes()) is None


def test_remaining_mapping_and_auth_data_format_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    mapping = {1: "packed", 2: b"\xaa\xbb"}
    assert decode_module._extract_mapping_string(mapping, (1, "fmt")) == "packed"
    assert decode_module._extract_mapping_bytes(mapping, (2, "authData")) == b"\xaa\xbb"

    summary = decode_module._summarize_bytes_for_json(b"\x01\x02")
    assert summary["length"] == 2
    assert summary["hex"] == "0102"

    auth_details, trailing = decode_module._format_auth_data_for_expanded_json(_auth_data_bytes())
    assert auth_details["signCount"] == 3
    assert isinstance(trailing, bytes)

    att_stmt = decode_module._format_att_stmt_for_expanded_json(
        {"sig": b"\xaa\xbb", "x5c": [], "alg": -7}
    )
    assert att_stmt["sig"] == "aabb"
    assert att_stmt["alg"] == -7


def test_remaining_interpret_request_map_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    make_request = {
        1: b"\x22" * 32,
        2: {"id": "example.com", "name": "Example"},
        3: {1: b"\x01", 2: b"alice"},
        4: [{"type": "public-key", "alg": -7}],
    }
    get_request = {1: "example.com", 2: b"\x22" * 32, 3: [{"id": b"\x01"}]}

    interpreted_make = decode_module._interpret_make_credential_request_map(make_request)
    interpreted_get = decode_module._interpret_get_assertion_request_map(get_request)

    assert interpreted_make is not None
    assert interpreted_get is not None
    assert any("clientDataHash" in key for key in interpreted_make)
    assert any("rpId" in key for key in interpreted_get)


def test_remaining_certificate_conversion_and_summary_helpers(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "serialize_attestation_certificate",
        lambda cert_bytes: {
            "derBase64": cbor2.dumps(cert_bytes).hex(),
            "pem": "PEM",
            "subject": "CN=Demo",
        },
        raising=False,
    )

    chain = decode_module._convert_certificate_chain([b"\x01\x02", "AQI=", {"derBase64": "AQI="}])
    assert len(chain) == 3

    converted_bytes = decode_module._convert_certificate_bytes("AQI=")
    assert "parsedX5c" in converted_bytes

    converted_payload = decode_module._convert_certificate_payload({"derBase64": "AQI=", "pem": "PEM"})
    assert converted_payload["raw"] == "0102"
    assert converted_payload["pem"] == "PEM"

    att_obj_summary = decode_module._format_attestation_object_summary(
        {
            "format": "Attestation object",
            "decoded": {"attestationFormat": "none", "authenticatorData": {"flags": {"value": 1}}},
            "binary": {"hex": "00" * 40},
        }
    )
    assert any("Detected type:\tAttestation object" == line for line in att_obj_summary)

    auth_summary = decode_module._format_authenticator_data_summary(
        {"format": "Authenticator data", "decoded": {"flags": {"value": 1}}, "binary": {"hex": "00" * 40}}
    )
    assert any("Detected type:\tAuthenticator data" == line for line in auth_summary)

    client_summary = decode_module._format_client_data_summary(
        {
            "format": "WebAuthn client data",
            "decoded": {
                "type": "webauthn.get",
                "challenge": {"raw": "AQID"},
                "origin": "https://example.com",
                "crossOrigin": False,
            },
        }
    )
    assert any("Detected type:\tWebAuthn client data" == line for line in client_summary)

    spki_lines = decode_module._build_subject_public_key_info_lines(
        {
            "type": "ECC",
            "keySize": 256,
            "curve": "secp256r1",
            "uncompressedPoint": "04aabb",
        }
    )
    assert any("Subject Public Key Info:" == line for line in spki_lines)

    assert decode_module._format_public_key_point_lines("04aabb")

    ext_header = decode_module._format_certificate_extension_header(
        {"oid": "1.2.3", "friendlyName": "Friendly", "includeOidInHeader": True}
    )
    assert ext_header == "1.2.3 (Friendly)"

    ext_lines = decode_module._build_certificate_extensions_lines(
        [{"oid": "1.2.3", "friendlyName": "Friendly", "value": {"Hex value": "aa"}}]
    )
    assert any("X509v3 extensions:" == line for line in ext_lines)

    assert decode_module._format_device_identifier_line("1.3.6.1.4.1.41482.1.1").endswith("Series)")

    json_lines = decode_module._format_json_block({"a": 1})
    assert json_lines and json_lines[0] == "{"
