from __future__ import annotations

import base64

import cbor2

from server.app.decoder import decode as decode_module


def test_build_credential_payload_covers_length_string_and_empty_public_key_payload():
    payload = decode_module._build_credential_payload(
        {
            "credentialId": {
                "hex": "aabb",
                "length": "len-as-text",
            },
            "publicKey": "not-a-mapping",
        },
        b"\x00" * 38,
        None,
    )

    assert payload["credentialId"] == "aabb"
    assert payload["credentialIdLength"] == "len-as-text"
    assert "publicKey" not in payload


def test_binary_extractors_and_authenticator_fallback_paths(monkeypatch, binary):
    assert decode_module._extract_hex_from_binary({"binary": {"hex": "aabb"}}) == "aabb"

    monkeypatch.setattr(
        binary,
        "_extract_authenticator_bytes_from_attestation",
        lambda _entry: b"from-attestation",
    )

    assert (
        decode_module._extract_authenticator_bytes(
            {
                "attestationObject": {
                    "raw": base64.b64encode(cbor2.dumps({"authData": b"\x00" * 37})).decode("ascii")
                }
            }
        )
        == b"from-attestation"
    )
