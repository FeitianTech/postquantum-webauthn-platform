import base64
import hashlib
import json

import cbor2
import pytest

from server.app.decoder.decode import text as decode_text
from server.app.decoder.encode import ctap_numeric as encode_ctap_numeric
from server.app.decoder.encode import handlers_basic as encode_handlers_basic
from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor
from server.app.decoder.encode import text as encode_text
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import b64u, unb64u


def _build_attestation_object(*, rp_id: str = "example.com", counter: int = 1, credential_id: bytes = b"codec-cred"):
    from fido2.cose import CoseKey
    from fido2.webauthn import (
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
    )

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


def test_encode_payload_text_cbor_is_deterministic_for_same_input():
    source = json.dumps({"z": 1, "a": [2, 3], "nested": {"x": "ok"}})

    first = encode_text.encode_payload_text(source, "cbor")
    second = encode_text.encode_payload_text(source, "cbor")

    assert first["data"]["binary"]["hex"] == second["data"]["binary"]["hex"]
    assert first["data"]["binary"]["base64url"] == second["data"]["binary"]["base64url"]


def test_normalize_encoding_format_aliases_and_case_insensitive():
    assert encode_handlers_basic._normalize_encoding_format("  JSON (binary)  ") == "json"
    assert encode_handlers_basic._normalize_encoding_format("CBOR (CANONICAL)") == "cbor"
    assert encode_handlers_basic._normalize_encoding_format("cbor (ctap/webauthn data)") == "ctap-webauthn"


def test_normalize_encoding_format_rejects_unknown_values():
    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_handlers_basic._normalize_encoding_format("totally-unknown")


def test_encode_ctap_webauthn_requires_mandatory_fields_for_make_credential_request():
    client_data_hash = base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("=")

    with pytest.raises(ValueError, match=r"Missing field 0x03 \(user\)"):
        encode_handlers_cbor._encode_ctap_webauthn_value(
            {
                "1": client_data_hash,
                "2": {"id": "example.com", "name": "Example RP"},
            }
        )


def test_decode_public_key_credential_preserves_key_fields_and_extensions():
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
        "id": b64u(raw_id),
        "rawId": b64u(raw_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "transports": ["internal", "hybrid"],
        "clientExtensionResults": {"credProps": {"rk": True}},
        "response": {
            "attestationObject": b64u(bytes(attestation_object)),
            "clientDataJSON": b64u(client_data_json),
        },
    }

    decoded = decode_text.decode_payload_text(json.dumps(credential))

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
    left_payload = json.dumps({"z": 1, "nested": {"b": 2, "a": 1}, "k": [3, {"y": 2, "x": 1}]})
    right_payload = json.dumps({"k": [3, {"x": 1, "y": 2}], "nested": {"a": 1, "b": 2}, "z": 1})

    left = encode_text.encode_payload_text(left_payload, "cbor")
    right = encode_text.encode_payload_text(right_payload, "cbor")

    assert left["data"]["binary"]["hex"] == right["data"]["binary"]["hex"]
    assert left["data"]["binary"]["base64url"] == right["data"]["binary"]["base64url"]


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


def test_classify_ctap_numeric_mapping_requires_field_two():
    with pytest.raises(ValueError, match=r"Missing field 0x02"):
        encode_ctap_numeric._classify_ctap_numeric_mapping({1: "example.com"})


def test_classify_ctap_numeric_mapping_rejects_short_auth_data_for_signature_response():
    with pytest.raises(
        ValueError,
        match=r"must contain authenticator data for GetAssertion response",
    ):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: "credential",
                2: b"\x00" * 36,
                3: b"\x01" * 64,
            }
        )


def test_classify_ctap_numeric_mapping_uses_field_two_length_boundaries_for_string_field_one():
    get_assertion_request = encode_ctap_numeric._classify_ctap_numeric_mapping(
        {
            1: "example.com",
            2: b"\x00" * 32,
        }
    )
    assert get_assertion_request == "getAssertionRequest"

    make_credential_response = encode_ctap_numeric._classify_ctap_numeric_mapping(
        {
            1: "example.com",
            2: b"\x00" * 37,
        }
    )
    assert make_credential_response == "makeCredentialResponse"

    with pytest.raises(ValueError, match=r"length is not valid"):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: "example.com",
                2: b"\x00" * 33,
            }
        )


def test_classify_ctap_numeric_mapping_requires_exact_client_data_hash_length_for_make_credential_request():
    with pytest.raises(
        ValueError,
        match=r"clientDataHash\) must be exactly 32 bytes",
    ):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: b"\x01" * 31,
                2: {"id": "example.com", "name": "Example"},
            }
        )


def test_encode_ctap_webauthn_rejects_duplicate_fields_after_key_normalization():
    with pytest.raises(ValueError, match=r"Duplicate field 0x01"):
        encode_handlers_cbor._encode_ctap_webauthn_value(
            {
                "1 (clientDataHash)": b64u(b"\x00" * 32),
                "01": b64u(b"\x11" * 32),
                "2": {"id": "example.com", "name": "Example"},
                "3": {
                    "id": b64u(b"user-id"),
                    "name": "user@example.com",
                    "displayName": "User",
                },
                "4": [{"type": "public-key", "alg": -7}],
            }
        )


def test_encode_ctap_webauthn_preserves_unknown_extra_numeric_fields():
    result = encode_handlers_cbor._encode_ctap_webauthn_value(
        {
            "1": "example.com",
            "2": b64u(b"\x22" * 32),
            "42": "debug-metadata",
        }
    )

    assert result["success"] is True
    assert result["type"] == "CBOR (CTAP/WebAuthn Data) (encoded getAssertionRequest)"
    encoded = result["data"]["encodedValue"]
    assert encoded["42"] == "debug-metadata"
    decoded = result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert decoded["42"] == "debug-metadata"


def test_encode_payload_text_cbor_is_deterministic_across_equivalent_permutations():
    variants = [
        json.dumps(
            {
                "z": 1,
                "nested": {"b": 2, "a": 1},
                "k": [3, {"y": 2, "x": 1}],
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
            }
        ),
        json.dumps(
            {
                "blob": {"beta": {"n": None, "m": True}, "alpha": [1, 2]},
                "k": [3, {"x": 1, "y": 2}],
                "nested": {"a": 1, "b": 2},
                "z": 1,
            }
        ),
        json.dumps(
            {
                "nested": {"a": 1, "b": 2},
                "z": 1,
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
                "k": [3, {"x": 1, "y": 2}],
            }
        ),
    ]

    encoded_hex_values = [
        encode_text.encode_payload_text(payload, "cbor")["data"]["binary"]["hex"]
        for payload in variants
    ]

    assert len(set(encoded_hex_values)) == 1


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
