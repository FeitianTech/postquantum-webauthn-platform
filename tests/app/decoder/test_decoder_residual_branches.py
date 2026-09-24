from __future__ import annotations

import hashlib

import pytest

from fido2 import cbor
from fido2.webauthn import AuthenticatorData


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


def test_decoder_residual_helpers_cover_remaining_parse_and_conversion_guards(monkeypatch, cbor_parser, ctap):
    decode_module = pytest.importorskip("server.app.decoder.decode")
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
        + bytes([AuthenticatorData.FLAG.AT])
        + (1).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (0).to_bytes(2, "big")
        + cbor.encode(5)
    )
    details, _, _ = decode_module._parse_authenticator_data_bytes(auth_with_cose_int)
    assert details["attestedCredentialData"]["credentialPublicKey"] == 5

    # Extensions that are not well-formed CBOR are shown as their bytes with
    # where they break, not dropped.
    broken_extensions = cbor.encode({"ext": True})[:-1]
    extension_payload = (
        hashlib.sha256(b"example.com").digest()
        + bytes([AuthenticatorData.FLAG.ED])
        + (1).to_bytes(4, "big")
        + broken_extensions
    )
    details, _, trailing = decode_module._parse_authenticator_data_bytes(extension_payload)
    assert details["extensions"] == broken_extensions.hex()
    assert details["parseError"] == (
        'extensions is not well-formed CBOR at authData offset 38: map key "ext" has no value'
    )
    assert trailing == b""

    # _format_json_block exception branch.
    assert decode_module._format_json_block(None) == []

    class _Unserializable:
        def __str__(self):
            return "fallback-string"

    assert decode_module._format_json_block(_Unserializable()) == ["fallback-string"]
