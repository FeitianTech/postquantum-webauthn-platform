import base64
import json

import cbor2
import pytest


def _pad_base64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


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
