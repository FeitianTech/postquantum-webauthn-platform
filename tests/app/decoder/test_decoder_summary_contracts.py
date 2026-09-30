import base64

import cbor2

from server.app.decoder.decode import answer as decode_answer
from server.app.decoder.decode import binary as decode_binary
from server.app.decoder.decode import certificates as decode_certificates
from tests.app.python_fido2_vectors import GSR2_DER as _GSR2_DER


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = bytes(range(32))
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (5).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def test_build_decoder_payload_cbor_adds_unique_qualifiers_and_ctap_sections():
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

    payload = decode_answer._build_decoder_payload(result)

    assert payload["success"] is True
    assert payload["type"].startswith("CBOR (")
    assert payload["type"].count("GetAssertion response") == 1
    assert "GetAssertion request" in payload["type"]
    # An "attStmt" key in expandedJson is not a makeCredential response.
    assert "MakeCredential response" not in payload["type"]
    assert payload["data"]["ctap"]["codeHex"] == "0x02"
    assert payload["data"]["expandedJson"]["attStmt"]["sig"] == "c0ffee"


def test_convert_attestation_entry_injects_certificate_when_x5c_is_empty():
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

    converted = decode_certificates.convert_attestation_entry(entry)

    assert converted["fmt"] == "packed"
    assert converted["attStmt"]["sig"] == "0102"
    assert len(converted["attStmt"]["x5c"]) == 1
    assert "parsedX5c" in converted["attStmt"]["x5c"][0]


def test_build_authenticator_data_payload_uses_bytes_and_details_to_build_credential_fields():
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

    payload = decode_answer._build_authenticator_data_payload(auth_bytes, details, -7)

    assert payload["rpIdHash"] == bytes(range(32)).hex()
    assert payload["counter"] == 5
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256 (ECDSA)"


def test_extract_bytes_from_binary_prefers_hex_and_then_base64url_raw():
    assert decode_binary._extract_bytes_from_binary({"hex": "AA BB"}) == b"\xaa\xbb"

    raw_value = base64.urlsafe_b64encode(b"\x01\x02\x03").decode("ascii").rstrip("=")
    assert decode_binary._extract_bytes_from_binary({"raw": raw_value}) == b"\x01\x02\x03"
    assert decode_binary._extract_bytes_from_binary({"raw": ""}) is None
