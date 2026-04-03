import base64
import hashlib
import json

import cbor2
import pytest


def _pad_base64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_attestation_object(*, rp_id: str = "example.com", counter: int = 1, credential_id: bytes = b"codec-cred"):
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

    cose_key = CoseKey.parse(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )
    attested_credential = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(rp_id.encode("utf-8")).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        counter=counter,
        credential_data=attested_credential,
    )
    return AttestationObject.create("none", auth_data, {})


def test_codec_api_rejects_non_json_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            data="payload",
            content_type="text/plain",
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Expected JSON payload."


def test_codec_api_requires_non_empty_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"payload": "   "},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Codec payload must be a non-empty string."


def test_codec_api_encode_requires_format():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "payload": "{\"a\":1}"},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Encoder format must be provided."


def test_codec_api_encode_returns_422_for_unsupported_format():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "format": "unknown_format", "payload": "{\"a\":1}"},
        )

    assert response.status_code == 422
    assert response.get_json()["error"] == "Unsupported encoder format: unknown_format"


def test_codec_api_returns_422_for_invalid_decode_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": "g$"},
        )

    assert response.status_code == 422
    assert "Input does not appear to be valid" in response.get_json()["error"]


def test_codec_api_round_trip_cbor_encode_then_decode():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    original = {"beta": "value", "alpha": [1, 2, 3], "flag": True}

    with config_module.app.test_client() as client:
        encoded_response = client.post(
            "/api/codec",
            json={
                "mode": "encode",
                "format": "cbor",
                "payload": json.dumps(original),
            },
        )

        assert encoded_response.status_code == 200
        encoded_payload = encoded_response.get_json()
        assert encoded_payload["success"] is True

        encoded_b64url = encoded_payload["data"]["binary"]["base64url"]
        encoded_bytes = base64.urlsafe_b64decode(_pad_base64(encoded_b64url))
        assert cbor2.loads(encoded_bytes) == original

        decoded_response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": encoded_b64url},
        )

        assert decoded_response.status_code == 200
        decoded_payload = decoded_response.get_json()
        assert decoded_payload["success"] is True
        assert decoded_payload["type"].startswith("CBOR")


def test_encode_payload_text_cbor_is_deterministic_for_same_input():
    decoder_module = pytest.importorskip("server.app.decoder")

    source = json.dumps({"z": 1, "a": [2, 3], "nested": {"x": "ok"}})

    first = decoder_module.encode_payload_text(source, "cbor")
    second = decoder_module.encode_payload_text(source, "cbor")

    assert first["data"]["binary"]["hex"] == second["data"]["binary"]["hex"]
    assert first["data"]["binary"]["base64url"] == second["data"]["binary"]["base64url"]


def test_client_data_encode_decode_contract():
    decoder_module = pytest.importorskip("server.app.decoder")

    client_data = {
        "type": "webauthn.create",
        "challenge": "AQID",
        "origin": "https://example.com",
        "crossOrigin": False,
    }

    encoded = decoder_module.encode_payload_text(json.dumps(client_data), "webauthn client data")
    encoded_b64url = encoded["data"]["clientDataJSON"]["base64url"]

    decoded = decoder_module.decode_payload_text(encoded_b64url)

    assert decoded["success"] is True
    assert decoded["type"].startswith("WebAuthn client data")
    assert decoded["data"]["type"] == "webauthn.create"
    assert decoded["data"]["origin"] == "https://example.com"


def test_normalize_encoding_format_aliases_and_case_insensitive():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._normalize_encoding_format("  WebAuthn client data  ") == "client-data"
    assert encode_module._normalize_encoding_format("PUBLIC KEY CREDENTIAL") == "public-key-credential"
    assert encode_module._normalize_encoding_format("cbor (ctap/webauthn data)") == "ctap-webauthn"


def test_normalize_encoding_format_rejects_unknown_values():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_module._normalize_encoding_format("totally-unknown")


def test_encode_ctap_webauthn_requires_mandatory_fields_for_make_credential_request():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    client_data_hash = base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("=")

    with pytest.raises(ValueError, match=r"Missing field 0x03 \(user\)"):
        encode_module._encode_ctap_webauthn_value(
            {
                "1": client_data_hash,
                "2": {"id": "example.com", "name": "Example RP"},
            }
        )


def test_attestation_object_encode_decode_round_trip_contract():
    decoder_module = pytest.importorskip("server.app.decoder")

    attestation_object = _build_attestation_object(counter=7, credential_id=b"codec-attestation-1")
    attestation_object_b64url = _b64url(bytes(attestation_object))

    encoded = decoder_module.encode_payload_text(
        json.dumps({"attestationObject": attestation_object_b64url}),
        "attestation object",
    )

    assert encoded["success"] is True
    assert encoded["type"].startswith("Attestation object")
    assert encoded["data"]["attestationObject"]["binary"]["base64url"] == attestation_object_b64url

    decoded = decoder_module.decode_payload_text(attestation_object_b64url)

    assert decoded["success"] is True
    assert decoded["type"] == "Attestation object"
    assert decoded["data"]["attestationObject"]["fmt"] == "none"
    assert decoded["data"]["authenticatorData"]["counter"] == 7
    assert decoded["data"]["authenticatorData"]["flags"]["AT"] is True


def test_decode_public_key_credential_preserves_key_fields_and_extensions():
    decoder_module = pytest.importorskip("server.app.decoder")

    raw_id = b"codec-public-key-cred"
    attestation_object = _build_attestation_object(counter=3, credential_id=raw_id)
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": "AQID",
            "origin": "https://example.com",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    credential = {
        "id": _b64url(raw_id),
        "rawId": _b64url(raw_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "transports": ["internal", "hybrid"],
        "clientExtensionResults": {"credProps": {"rk": True}},
        "response": {
            "attestationObject": _b64url(bytes(attestation_object)),
            "clientDataJSON": _b64url(client_data_json),
        },
    }

    decoded = decoder_module.decode_payload_text(json.dumps(credential))

    assert decoded["success"] is True
    assert decoded["type"] == "PublicKeyCredential"

    payload = decoded["data"]
    assert payload["credential"]["authenticatorAttachment"] == "platform"
    assert payload["credential"]["transports"] == ["internal", "hybrid"]
    assert payload["clientExtensionResults"]["credProps"]["rk"] is True
    assert payload["attestationObject"]["fmt"] == "none"
    assert payload["clientDataJSON"]["type"] == "webauthn.create"
    assert payload["authenticatorData"]["counter"] == 3


def test_encode_payload_text_cbor_is_canonical_for_equivalent_key_orderings():
    decoder_module = pytest.importorskip("server.app.decoder")

    left_payload = json.dumps({"z": 1, "nested": {"b": 2, "a": 1}, "k": [3, {"y": 2, "x": 1}]})
    right_payload = json.dumps({"k": [3, {"x": 1, "y": 2}], "nested": {"a": 1, "b": 2}, "z": 1})

    left = decoder_module.encode_payload_text(left_payload, "cbor")
    right = decoder_module.encode_payload_text(right_payload, "cbor")

    assert left["data"]["binary"]["hex"] == right["data"]["binary"]["hex"]
    assert left["data"]["binary"]["base64url"] == right["data"]["binary"]["base64url"]


def test_codec_api_decodes_attestation_object_contract():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    attestation_object = _build_attestation_object(counter=9, credential_id=b"codec-api-attestation")
    payload = _b64url(bytes(attestation_object))

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": payload},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["type"] == "Attestation object"
    assert data["data"]["attestationObject"]["fmt"] == "none"
    assert data["data"]["authenticatorData"]["counter"] == 9
