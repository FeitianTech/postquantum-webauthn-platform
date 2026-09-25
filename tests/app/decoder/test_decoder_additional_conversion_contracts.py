from __future__ import annotations

import base64
import hashlib
import json

import pytest

from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData


def _build_auth_data_bytes() -> bytes:
    credential_id = b"decoder-extra-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        9,
        credential_data,
    )
    return bytes(auth_data)


def _build_attestation_bytes() -> bytes:
    auth_data = _build_auth_data_bytes()
    attestation = AttestationObject.create("none", AuthenticatorData(auth_data), {})
    return bytes(attestation)


def test_describe_client_data_from_bytes_success_and_collected_client_data_fallback(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    raw_json = {
        "type": "webauthn.create",
        "challenge": "AQID",
        "origin": "https://example.com",
        "crossOrigin": False,
    }
    payload = json.dumps(raw_json).encode("utf-8")

    success = decode_module._describe_client_data_from_bytes(payload)
    assert success["type"] == "webauthn.create"
    assert success["origin"] == "https://example.com"
    assert success["crossOrigin"] is False
    assert success["challenge"]["raw"] == "AQID"

    class _BrokenClientData:
        def __init__(self, _payload):
            raise ValueError("broken collected client data")

    monkeypatch.setattr(pipeline, "CollectedClientData", _BrokenClientData)
    fallback = decode_module._describe_client_data_from_bytes(payload)
    assert fallback["type"] == "webauthn.create"
    assert fallback["challenge"]["raw"] == "AQID"


def test_describe_authenticator_data_bytes_includes_flags_and_attested_credential_details():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = _build_auth_data_bytes()
    details = decode_module._describe_authenticator_data_bytes(auth_bytes)

    assert details["rpIdHash"]["hex"] == hashlib.sha256(b"example.com").hexdigest()
    assert details["flags"]["userPresent"] is True
    assert details["flags"]["attestedCredentialDataIncluded"] is True
    assert details["signCount"] == 9
    assert details["attestedCredentialData"]["credentialId"]["hex"]


def test_parse_attestation_object_reads_null_and_float_statement_values_as_what_they_are(monkeypatch, pipeline):
    # fido2.cbor read all of major type 7 as a boolean: null became False and
    # 1.5 became False, with its four payload bytes left to be misread.
    decode_module = pytest.importorskip("server.app.decoder.decode")
    real_extract_attestation_certificate = decode_module._extract_attestation_certificate
    monkeypatch.setattr(pipeline, "_extract_attestation_certificate", lambda _stmt: {"parsed": True})

    auth_data = _build_auth_data_bytes()
    statement = b"\xa3" + b"\x61n\xf6" + b"\x61f\xfa\x3f\xc0\x00\x00" + b"\x63x5c\x81\x4acert-bytes"
    attestation = (
        b"\xa3"
        + b"\x63fmt\x66packed"
        + b"\x67attStmt" + statement
        + b"\x68authData\x58" + bytes([len(auth_data)]) + auth_data
    )

    parsed = decode_module._parse_attestation_object(attestation)

    assert parsed["attestationFormat"] == "packed"
    assert parsed["attestationStatement"]["n"] is None
    assert parsed["attestationStatement"]["f"] == 1.5
    assert parsed["attestationCertificate"] == {"parsed": True}
    assert parsed["cbor"]["fmt"] == "packed"
    assert parsed["authenticatorData"]["signCount"] == 9

    with pytest.raises(ValueError, match="Extraneous data"):
        decode_module._parse_attestation_object(attestation + b"\x00")

    assert real_extract_attestation_certificate({"x5c": ["%%%"]}) is None


def test_convert_attestation_statement_and_certificate_chain_paths(monkeypatch, response):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        response,
        "serialize_attestation_certificate",
        lambda cert_bytes: {
            "derBase64": base64.b64encode(cert_bytes).decode("ascii"),
            "pem": "PEM",
            "fingerprints": {"sha256": "x"},
        },
    )

    details = {
        "attestationStatement": {
            "alg": -7,
            "x5c": [b"\x01\x02", "AQI=", {"derBase64": "AQI="}],
        }
    }
    statement = decode_module._convert_attestation_statement(details)

    assert statement["alg"] == -7
    assert len(statement["x5c"]) == 3
    assert statement["x5c"][0]["raw"] == "0102"
    assert "parsedX5c" in statement["x5c"][1]

    cbor_fallback = decode_module._convert_attestation_statement(
        {"cbor": {"attStmt": {"sig": b"\xaa"}}}
    )
    assert cbor_fallback["sig"] == "aa"


def test_build_authenticator_payload_flag_and_credential_helpers_cover_fallback_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = _build_auth_data_bytes()
    payload = decode_module._build_authenticator_data_payload(auth_bytes, {}, fallback_alg=-7)

    assert payload["raw"] == auth_bytes.hex()
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["counter"] == 9
    assert payload["credential"]["publicKey"]["alg"] == "ES256 (ECDSA)"

    assert decode_module._build_flag_payload(None, None, auth_byte_length=12) == {}
    mapped_flags = decode_module._build_flag_payload(
        {
            "value": 0x45,
            "bitfield": "0b01000101",
            "userPresent": True,
            "userVerified": True,
            "backupEligible": False,
            "backupState": False,
            "attestedCredentialData": True,
            "extensionData": False,
        },
        None,
        auth_byte_length=37,
    )
    assert mapped_flags["hex"] == "45"
    assert mapped_flags["UP"] is True
    assert mapped_flags["AT"] is True

    credential_only = decode_module._build_credential_payload(
        {
            "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
            "aaguidHex": "00112233445566778899aabbccddeeff",
            "credentialId": {"hex": "abcd", "length": 2},
            "publicKey": {"alg": -7, -2: "AQID", -3: "BAUG"},
        },
        None,
        fallback_alg=-7,
    )
    assert credential_only["credentialId"] == "abcd"
    assert credential_only["publicKey"]["alg"] == "ES256 (ECDSA)"


def test_client_data_entry_response_extras_and_base_type_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    converted_client_data = decode_module._convert_client_data_entry(
        {
            "details": {
                "type": "webauthn.get",
                "challenge": {"base64url": "AQID"},
                "origin": "https://example.com",
                "crossOrigin": 1,
            }
        }
    )
    assert converted_client_data["type"] == "webauthn.get"
    assert converted_client_data["challenge"] == "AQID"
    assert converted_client_data["crossOrigin"] == 1

    extras = decode_module._collect_response_extras(
        {
            "signature": b"\x01\x02",
            "userHandle": None,
            "publicKey": {1: b"\xaa"},
            "publicKeyAlgorithm": -7,
        }
    )
    assert "userHandle" not in extras
    assert "signature" in extras
    assert extras["publicKeyAlgorithm"] == -7

    assert decode_module._base_type("CBOR (GetAssertion response)") == "CBOR"
    assert decode_module._base_type(None) == "Decoded data"
