"""Tests of codec behavior."""

import base64
import json

import cbor2

from server.app.decoder.encode import text as encode_text
from tests.app.decoder.credential_bytes import _build_attestation_object
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import b64u, unb64u


def test_codec_api_rejects_non_json_payload():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            data="payload",
            content_type="text/plain",
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Expected JSON payload."


def test_codec_api_requires_non_empty_payload():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"payload": "   "},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Codec payload must be a non-empty string."


def test_codec_api_encode_requires_format():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "payload": "{\"a\":1}"},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Encoder format must be provided."


def test_codec_api_encode_returns_422_for_unsupported_format():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "format": "unknown_format", "payload": "{\"a\":1}"},
        )

    assert response.status_code == 422
    assert response.get_json()["error"] == "Unsupported encoder format: unknown_format"


def test_codec_api_returns_422_for_invalid_decode_payload():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": "g$"},
        )

    assert response.status_code == 422
    assert "Input does not appear to be valid" in response.get_json()["error"]


def test_codec_api_round_trip_cbor_encode_then_decode():
    original = {"beta": "value", "alpha": [1, 2, 3], "flag": True}

    with entry_app().test_client() as client:
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
        encoded_bytes = unb64u(encoded_b64url)
        assert cbor2.loads(encoded_bytes) == original

        decoded_response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": encoded_b64url},
        )

        assert decoded_response.status_code == 200
        decoded_payload = decoded_response.get_json()
        assert decoded_payload["success"] is True
        assert decoded_payload["type"].startswith("CBOR")


def test_codec_api_decodes_attestation_object_contract():
    attestation_object = _build_attestation_object(counter=9, credential_id=b"codec-api-attestation")
    payload = b64u(bytes(attestation_object))

    with entry_app().test_client() as client:
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


def test_codec_api_encode_pem_binary_contract():
    payload_bytes = bytes(range(48))
    request_payload = {
        "mode": "encode",
        "format": "pem",
        "payload": json.dumps(
            {
                "value": {"base64url": b64u(payload_bytes)},
                "pemLabel": "demo cert",
            }
        ),
    }

    with entry_app().test_client() as client:
        response = client.post("/api/codec", json=request_payload)

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["type"] == "PEM (encoded)"

    pem_lines = data["data"]["pem"].splitlines()
    assert pem_lines[0] == "-----BEGIN DEMO_CERT-----"
    assert pem_lines[-1] == "-----END DEMO_CERT-----"
    restored = base64.b64decode("".join(pem_lines[1:-1]))
    assert restored == payload_bytes


def test_codec_api_encode_der_from_nested_binary_payload():
    payload_bytes = b"\x10\x11\x12\x13\x14"
    request_payload = {
        "mode": "encode",
        "format": "der",
        "payload": json.dumps({"binary": {"base64url": b64u(payload_bytes)}}),
    }

    with entry_app().test_client() as client:
        response = client.post("/api/codec", json=request_payload)

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["type"] == "DER (encoded)"
    assert data["data"]["binary"]["hex"] == payload_bytes.hex()
    assert data["data"]["derBase64"] == base64.b64encode(payload_bytes).decode("ascii")


def test_codec_api_encode_maps_value_error_to_422(monkeypatch):
    monkeypatch.setattr(
        encode_text,
        "encode_payload_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad encode request")),
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "format": "cbor", "payload": "{}"},
        )

    assert response.status_code == 422
    assert response.get_json() == {"error": "bad encode request"}


def test_codec_api_encode_maps_unexpected_error_to_500(monkeypatch):
    monkeypatch.setattr(
        encode_text,
        "encode_payload_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("encoder crashed")),
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "encode", "format": "cbor", "payload": "{}"},
        )

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to encode payload."}
