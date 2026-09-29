from __future__ import annotations

import base64

import cbor2
import pytest


def test_build_credential_payload_covers_length_string_and_empty_public_key_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

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
    decode_module = pytest.importorskip("server.app.decoder.decode")

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


def test_append_authenticator_section_uses_response_context_public_key_algorithm(monkeypatch, summary):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    captured = {}

    def _collect(attested, auth_bytes, fallback_alg=None):
        captured["fallback_alg"] = fallback_alg
        return {
            "credential_lines": ["cred"],
            "aaguid_lines": ["aaguid"],
            "credential_id": "id",
            "algorithm": "ES256",
            "public_key_lines": ["pk"],
        }

    monkeypatch.setattr(summary, "_collect_attested_info", _collect)

    lines = []
    decode_module._extend_with_authenticator_details(
        lines,
        {
            "rpIdHash": {"hex": "abcd"},
            "flags": {"UP": True},
            "signCount": 1,
            "attestedCredentialData": {"aaguidHex": "aa"},
        },
        None,
        response_context={"publicKeyAlgorithm": -7},
    )

    assert captured["fallback_alg"] == -7
    assert any("Credential data" in line for line in lines)
