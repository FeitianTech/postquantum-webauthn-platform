from __future__ import annotations

import hashlib

import pytest


def test_build_labeled_ctap_map_covers_seen_key_seen_label_and_string_missing_handler():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    result = decode_module._build_labeled_ctap_map(
        mapping={1: "present"},
        labels={1: "shared", 2: "shared", 4: "four", 5: "five"},
        handlers={"4": lambda _value: "handled-via-string"},
        missing_keys=(1, 2, 4, 5),
    )

    assert result["1 (shared)"] == "present"
    assert result["4 (four)"] == "handled-via-string"
    assert result["5 (five)"] is None


def test_decoder_residual_helpers_cover_remaining_parse_and_conversion_guards(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")
    auth_data_cls = decode_module.AuthenticatorData

    # _derive_alg_from_auth_data branches.
    monkeypatch.setattr(
        decode_module,
        "AuthenticatorData",
        lambda _raw: (_ for _ in ()).throw(ValueError("bad-auth-data")),
        raising=False,
    )
    assert decode_module._derive_alg_from_auth_data(b"bad") is None

    monkeypatch.setattr(
        decode_module,
        "AuthenticatorData",
        lambda _raw: type("_Auth", (), {"credential_data": None})(),
        raising=False,
    )
    assert decode_module._derive_alg_from_auth_data(b"ok") is None
    monkeypatch.setattr(decode_module, "AuthenticatorData", auth_data_cls, raising=False)

    # _extract_attestation_certificate and _convert_certificate_bytes/payload guards.
    assert decode_module._extract_attestation_certificate("not-a-map") is None
    assert decode_module._extract_attestation_certificate({"x5c": ["A"]}) is None

    assert decode_module._convert_certificate_bytes("A") == {}
    assert decode_module._convert_certificate_bytes(123) == {}
    assert decode_module._convert_certificate_payload("not-a-map") == {}
    assert decode_module._convert_certificate_payload({"derBase64": "A"})["parsedX5c"]["derBase64"] == "A"

    # _convert_client_data_entry and _format_certificate_extension_header edge paths.
    assert decode_module._convert_client_data_entry("not-a-map") == {}
    assert decode_module._convert_client_data_entry({"details": "not-a-map"}) == {}
    challenge_payload = decode_module._convert_client_data_entry(
        {"details": {"type": "webauthn.create", "challenge": {"nested": "value"}}}
    )
    assert challenge_payload["challenge"] == {"nested": "value"}

    assert decode_module._format_certificate_extension_header({}) is None
    assert (
        decode_module._format_certificate_extension_header(
            {"includeOidInHeader": False, "friendlyName": "Friendly"}
        )
        == "Friendly"
    )

    # _parse_authenticator_data_bytes branch for non-mapping COSE value and extension decode exceptions.
    auth_with_cose_int = (
        b"\x01" * 32
        + bytes([decode_module.AuthenticatorData.FLAG.AT])
        + (1).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (0).to_bytes(2, "big")
        + decode_module.cbor.encode(5)
    )
    details, _, _ = decode_module._parse_authenticator_data_bytes(auth_with_cose_int)
    assert details["attestedCredentialData"]["credentialPublicKey"] == 5

    extension_payload = (
        hashlib.sha256(b"example.com").digest()
        + bytes([decode_module.AuthenticatorData.FLAG.ED])
        + (1).to_bytes(4, "big")
        + decode_module.cbor.encode({"ext": True})
    )

    monkeypatch.setattr(
        decode_module,
        "_lenient_decode_from",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("decode-error")),
        raising=False,
    )
    details, _, trailing = decode_module._parse_authenticator_data_bytes(extension_payload)
    assert "extensions" not in details
    assert trailing == decode_module.cbor.encode({"ext": True})

    # _format_json_block exception branch.
    assert decode_module._format_json_block(None) == []

    class _Unserializable:
        def __str__(self):
            return "fallback-string"

    assert decode_module._format_json_block(_Unserializable()) == ["fallback-string"]