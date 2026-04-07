import base64
import hashlib

import cbor2
import pytest

from tests.fido2.attestation.test_attestation import _GSR2_DER


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = bytes(range(32))
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (5).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def test_format_certificate_summary_includes_extension_and_fingerprint_sections():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    decoded = {
        "version": {"display": "3 (0x2)"},
        "serialNumber": {"decimal": "1234", "hex": "0x04d2"},
        "signatureAlgorithm": "sha256WithRSAEncryption",
        "issuer": "CN=Issuer Root",
        "validity": {
            "notBefore": "2024-01-01T00:00:00Z",
            "notAfter": "2026-01-01T00:00:00+00:00",
        },
        "subject": "CN=Authenticator",
        "publicKeyInfo": {
            "type": "id-ecPublicKey",
            "keySize": 256,
            "uncompressedPoint": "04AABBCCDDEE",
            "algorithm": {"namedCurve": "P-256"},
        },
        "extensions": [
            {"displayHeader": "Basic Constraints", "value": "CA:FALSE"},
            {
                "oid": "1.3.6.1.4.1.41482.1.1",
                "friendlyName": "deviceIdentifier",
                "value": {
                    "Hex value": "DEADBEEF",
                    "Device identifier": "1.3.6.1.4.1.41482.1.1",
                },
            },
            {
                "oid": "2.5.29.14",
                "value": {"Subject Key Identifier": "A1B2C3D4"},
            },
        ],
        "signature": {"algorithm": "sha256WithRSAEncryption", "hex": "aabbccdd"},
        "fingerprints": {
            "md5": "00112233445566778899aabbccddeeff",
            "sha1": "aabbccddeeff00112233445566778899aabbccdd",
            "sha256": "00112233445566778899aabbccddeeff" * 2,
        },
    }

    summary = decode_module._format_result_summary(
        {"format": "X.509 certificate (DER)", "decoded": decoded}
    )

    assert "Detected type:\tX.509 certificate" in summary
    assert "Version: 3 (0x2)" in summary
    assert "X509v3 extensions:" in summary
    assert "1.3.6.1.4.1.41482.1.1 (Security Key by Yubico Series)" in summary
    assert "Fingerprint:" in summary
    assert "Subject key identifier:" in summary
    assert "a1:b2:c3:d4" in summary.lower()


def test_format_certificate_time_normalizes_valid_timestamp_and_preserves_invalid_text():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._format_certificate_time("2026-01-01T12:34:56Z") == "2026-01-01T12:34:56"
    assert decode_module._format_certificate_time("not-a-time") == "not-a-time"
    assert decode_module._format_certificate_time("   ") is None


def test_build_subject_key_identifier_lines_falls_back_to_subject_public_key_info_digest():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    spki_bytes = b"subject-public-key-info"
    decoded = {
        "publicKeyInfo": {
            "subjectPublicKeyInfoBase64": base64.b64encode(spki_bytes).decode("ascii")
        }
    }

    lines = decode_module._build_subject_key_identifier_lines(decoded)

    assert lines == decode_module.format_hex_bytes_lines(hashlib.sha1(spki_bytes).digest())


def test_build_decoder_payload_cbor_adds_unique_qualifiers_and_ctap_sections():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    result = {
        "format": "CBOR",
        "decoded": {
            "ctap": {
                "meaning": "AuthenticatorGetAssertion command",
                "kind": "command",
                "code": 2,
                "codeHex": "0x02",
            },
            "ctapDecoded": {
                "getAssertionResponse": {"signature": "deadbeef"},
                "getAssertionRequest": {"rpId": "example.com"},
            },
            "expandedJson": {
                "signature": "deadbeef",
                "attStmt": {"sig": "c0ffee"},
            },
            "decodedValue": {"k": "v"},
        },
    }

    payload = decode_module._build_decoder_payload(result)

    assert payload["success"] is True
    assert payload["type"].startswith("CBOR (")
    assert payload["type"].count("GetAssertion response") == 1
    assert "GetAssertion request" in payload["type"]
    assert "MakeCredential response" in payload["type"]
    assert payload["data"]["ctap"]["codeHex"] == "0x02"
    assert payload["data"]["expandedJson"]["attStmt"]["sig"] == "c0ffee"


def test_convert_attestation_entry_injects_certificate_when_x5c_is_empty():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    der_b64 = base64.b64encode(_GSR2_DER).decode("ascii")
    entry = {
        "raw": "raw-attestation",
        "details": {
            "attestationFormat": "packed",
            "attestationStatement": {
                "alg": -7,
                "sig": b"\x01\x02",
                "x5c": [],
            },
            "attestationCertificate": {
                "derBase64": der_b64,
                "pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----",
                "subject": "CN=Demo",
            },
        },
    }

    converted = decode_module._convert_attestation_entry(entry)

    assert converted["fmt"] == "packed"
    assert converted["attStmt"]["sig"] == "0102"
    assert len(converted["attStmt"]["x5c"]) == 1
    assert "parsedX5c" in converted["attStmt"]["x5c"][0]


def test_build_authenticator_data_payload_uses_bytes_and_details_to_build_credential_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = _build_authenticator_data_bytes()
    details = {
        "flags": {
            "value": 0x45,
            "bitfield": "0b01000101",
            "userPresent": True,
            "userVerified": True,
            "backupEligibility": False,
            "backupState": False,
            "attestedCredentialDataIncluded": True,
            "extensionDataIncluded": False,
        },
        "signCount": 5,
        "attestedCredentialData": {
            "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
            "aaguidHex": "00112233445566778899aabbccddeeff",
            "credentialId": {"hex": "10203040", "length": 4},
            "publicKey": {1: 2, 3: -7, -2: "AQID", -3: "BAUG"},
        },
    }

    payload = decode_module._build_authenticator_data_payload(auth_bytes, details, -7)

    assert payload["rpIdHash"] == bytes(range(32)).hex()
    assert payload["counter"] == 5
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256"


def test_extend_with_client_data_details_outputs_defaults_and_structured_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    missing_lines = []
    decode_module._extend_with_client_data_details(missing_lines, None)
    assert "Client data:\t(none)" in missing_lines
    assert "Type:\t(none)" in missing_lines

    details = {
        "rawJson": {
            "type": "webauthn.create",
            "challenge": "challenge-raw",
            "origin": "https://example.com",
            "crossOrigin": False,
        },
        "type": "webauthn.create",
        "challenge": {"hex": "aabbcc"},
        "origin": "https://example.com",
        "crossOrigin": False,
    }

    lines = []
    decode_module._extend_with_client_data_details(lines, details)

    assert any(line == "Type:\twebauthn.create" for line in lines)
    assert any(line == "Challenge:\taabbcc" for line in lines)
    assert any(line == "Origin:\thttps://example.com" for line in lines)
    assert any(line == "Cross-origin:\tfalse" for line in lines)


def test_format_cbor_summary_includes_ctap_interpretation_and_decoded_blocks():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    summary = decode_module._format_result_summary(
        {
            "format": "CBOR",
            "decoded": {
                "ctap": {
                    "meaning": "Success status",
                    "kind": "status",
                    "codeHex": "0x00",
                    "payloadLength": 17,
                },
                "ctapDecoded": {
                    "makeCredentialResponse": {"fmt": "packed"},
                    "getAssertionResponse": {"signature": "deadbeef"},
                },
                "expandedJson": {"fmt": "packed", "attStmt": {"alg": -7}},
                "decodedValue": {"fmt": "packed"},
            },
        }
    )

    assert "Detected type:\tCBOR (Success status)" in summary
    assert "CTAP interpretation:\tMakeCredential response, GetAssertion response" in summary
    assert "Expanded JSON" in summary
    assert "Decoded value" in summary


def test_extract_bytes_from_binary_prefers_hex_and_then_base64url_raw():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._extract_bytes_from_binary({"hex": "AA BB"}) == b"\xaa\xbb"

    raw_value = base64.urlsafe_b64encode(b"\x01\x02\x03").decode("ascii").rstrip("=")
    assert decode_module._extract_bytes_from_binary({"raw": raw_value}) == b"\x01\x02\x03"
    assert decode_module._extract_bytes_from_binary({"raw": ""}) is None


def test_extend_with_attestation_section_without_certificates_emits_placeholder_block():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = []
    decode_module._extend_with_attestation_section(
        lines,
        {"hex": "aabb"},
        {"attestationFormat": "packed", "attestationCertificate": {"subject": "CN=Demo"}},
        include_certificates=False,
    )

    assert "Attestation object:\taabb" in lines
    assert "Att. format:\tpacked" in lines
    assert "Att. certificates:\t" in lines
