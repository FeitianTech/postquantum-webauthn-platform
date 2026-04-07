import base64
import hashlib
import json

import cbor2
import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_attestation_and_auth_data() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

    credential_id = b"pipeline-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        2,
        credential_data,
    )
    attestation = AttestationObject.create("none", auth_data, {})
    return bytes(attestation), bytes(auth_data)


def test_build_decoder_payload_for_cbor_deduplicates_qualifiers_and_normalizes_malformed():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = decode_module._build_decoder_payload(
        {
            "format": "CBOR",
            "decoded": {
                "ctap": {"meaning": "AuthenticatorGetAssertion command"},
                "ctapDecoded": {
                    "getAssertionRequest": {"rpId": "example.com"},
                    "getAssertionResponse": {"signature": "deadbeef"},
                },
                "expandedJson": {
                    "signature": "deadbeef",
                },
            },
            "malformed": "not-a-list",
        }
    )

    assert payload["success"] is True
    assert payload["type"].startswith("CBOR (")
    assert payload["type"].count("GetAssertion response") == 1
    assert payload["type"].count("GetAssertion request") == 1
    assert payload["malformed"] == []


def test_convert_result_to_data_covers_json_cbor_and_fallback_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._convert_result_to_data("JSON", {"decoded": {"a": 1}}) == {
        "json": {"a": 1}
    }

    cbor_payload = decode_module._convert_result_to_data(
        "CBOR",
        {
            "decoded": {
                "ctapDecoded": {1: {"sig": b"\x01\x02"}},
                "expandedJson": {"attStmt": {"sig": b"\x03\x04"}},
                "decodedValue": {"k": "v"},
                "ctap": {"code": 2},
            }
        },
    )
    assert "ctapDecoded" in cbor_payload
    assert "expandedJson" in cbor_payload
    assert "decodedValue" in cbor_payload
    assert cbor_payload["ctap"]["code"] == 2

    fallback = decode_module._convert_result_to_data(
        "Unknown type",
        {"decoded": None, "binary": {"hex": "aabb"}},
    )
    assert fallback == {"hex": "aabb"}


def test_convert_public_key_credential_and_attestation_object_data_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    attestation_bytes, auth_data_bytes = _build_attestation_and_auth_data()
    attestation_b64 = base64.b64encode(attestation_bytes).decode("ascii")

    public_key_result = {
        "decoded": {
            "id": _b64url(b"cred"),
            "type": "public-key",
            "response": {
                "attestationObject": {
                    "raw": attestation_b64,
                    "details": {
                        "attestationFormat": "none",
                        "attestationStatement": {"alg": -7},
                        "authenticatorData": {
                            "flags": {"value": 0x41, "userPresent": True, "attestedCredentialData": True},
                            "signCount": 2,
                        },
                    },
                },
                "clientDataJSON": {
                    "details": {
                        "type": "webauthn.create",
                        "challenge": "AQID",
                        "origin": "https://example.com",
                        "crossOrigin": False,
                    }
                },
            },
            "clientExtensionResults": {"credProps": {"rk": True}},
        }
    }

    converted_public = decode_module._convert_result_to_data("PublicKeyCredential", public_key_result)
    assert converted_public["credential"]["type"] == "public-key"
    assert converted_public["attestationObject"]["fmt"] == "none"
    assert converted_public["clientExtensionResults"]["credProps"]["rk"] is True

    attestation_result = {
        "decoded": {
            "attestationFormat": "packed",
            "attestationStatement": {"alg": -7},
            "extensions": {"credProps": {"rk": True}},
            "authenticatorData": {
                "flags": {
                    "value": 0x41,
                    "userPresent": True,
                    "attestedCredentialDataIncluded": True,
                },
                "signCount": 2,
            },
        },
        "binary": {"base64": attestation_b64},
    }

    converted_attestation = decode_module._convert_result_to_data("Attestation object", attestation_result)
    assert converted_attestation["attestationObject"]["raw"] == attestation_b64
    assert converted_attestation["extensions"]["credProps"]["rk"] is True
    assert converted_attestation["authenticatorData"]["counter"] == 2
    assert converted_attestation["authenticatorData"]["flags"]["AT"] is True


def test_convert_authenticator_clientdata_and_certificate_result_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    _attestation_bytes, auth_data_bytes = _build_attestation_and_auth_data()

    auth_result = {
        "decoded": {
            "flags": {"value": 0x41, "userPresent": True, "attestedCredentialDataIncluded": True},
            "signCount": 2,
        },
        "binary": {"hex": auth_data_bytes.hex()},
    }
    converted_auth = decode_module._convert_result_to_data("Authenticator data", auth_result)
    assert converted_auth["raw"] == auth_data_bytes.hex()
    assert converted_auth["counter"] == 2

    client_result = {
        "decoded": {
            "type": "webauthn.get",
            "challenge": "AQID",
            "origin": "https://example.com",
            "crossOrigin": True,
        }
    }
    converted_client = decode_module._convert_result_to_data("WebAuthn client data", client_result)
    assert converted_client["type"] == "webauthn.get"
    assert converted_client["crossOrigin"] is True

    certificate_bytes = b"\x30\x82\x01\x00"
    certificate_result = {
        "decoded": {
            "certificates": [
                {
                    "derBase64": base64.b64encode(certificate_bytes).decode("ascii"),
                    "pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----",
                }
            ]
        }
    }
    converted_certificate = decode_module._convert_result_to_data(
        "X.509 certificate", certificate_result
    )
    assert converted_certificate["certificates"]
    assert converted_certificate["certificates"][0]["raw"] == certificate_bytes.hex()


def test_prepare_decoder_response_and_detector_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    prepared = decode_module._prepare_decoder_response(
        {
            "format": "JSON",
            "decoded": {"ok": True},
        }
    )
    assert prepared["success"] is True
    assert prepared["type"] == "JSON"

    credential_candidate = {
        "id": "credential-id",
        "type": "public-key",
        "response": {"clientDataJSON": _b64url(b"{}")},
    }
    assert decode_module._is_public_key_credential(credential_candidate) is True
    assert decode_module._is_public_key_credential({"response": {}}) is False

    client_data_candidate = {
        "type": "webauthn.create",
        "challenge": "AQID",
        "origin": "https://example.com",
    }
    assert decode_module._is_client_data_dict(client_data_candidate) is True
    assert decode_module._is_client_data_dict({"type": "x", "challenge": "AQID"}) is False


def test_decode_payload_text_json_public_key_credential_and_cbor_roundtrip():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    attestation_bytes, _auth_data_bytes = _build_attestation_and_auth_data()
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": "AQID",
            "origin": "https://example.com",
        }
    ).encode("utf-8")

    credential = {
        "id": _b64url(b"cred-id"),
        "rawId": _b64url(b"cred-id"),
        "type": "public-key",
        "response": {
            "attestationObject": _b64url(attestation_bytes),
            "clientDataJSON": _b64url(client_data_json),
        },
    }

    decoded_credential = decode_module.decode_payload_text(json.dumps(credential))
    assert decoded_credential["success"] is True
    assert decoded_credential["type"] == "PublicKeyCredential"
    assert decoded_credential["data"]["attestationObject"]["fmt"] in {
        "none",
        "packed",
    }

    cbor_payload = cbor2.dumps({1: b"\x00" * 32, 2: "example.com"})
    decoded_cbor = decode_module.decode_payload_text(_b64url(cbor_payload))
    assert decoded_cbor["success"] is True
    assert decoded_cbor["type"].startswith("CBOR")
    assert "decodedValue" in decoded_cbor["data"]
