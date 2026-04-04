from __future__ import annotations

import base64
import hashlib

import pytest


def test_build_labeled_ctap_map_resolves_handlers_and_missing_keys_across_all_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    mapping = {
        1: "alpha-value",
        9: "int-handler-value",
        3: "string-handler-value",
    }
    labels = {
        1: "alpha",
        9: "nine",
        10: "ten",
        12: "twelve",
    }
    handlers = {
        "alpha": lambda value: f"label:{value}",
        9: lambda value: f"int:{value}",
        "3": lambda value: f"str:{value}",
        "ten": lambda value: "missing-ten" if value is None else value,
        11: lambda value: "missing-eleven" if value is None else value,
    }

    result = decode_module._build_labeled_ctap_map(
        mapping,
        labels,
        handlers,
        missing_keys=(10, 11, 12),
    )

    assert result["1 (alpha)"] == "label:alpha-value"
    assert result["9 (nine)"] == "int:int-handler-value"
    assert result["3"] == "str:string-handler-value"
    assert result["10 (ten)"] == "missing-ten"
    assert result["11"] == "missing-eleven"
    assert result["12 (twelve)"] is None


def test_looks_like_get_assertion_request_rejects_signature_or_authdata_binary_shapes():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._looks_like_get_assertion_request("not-a-map") is False
    assert (
        decode_module._looks_like_get_assertion_request(
            {"rpId": "example.com", "clientDataHash": "not-binary"}
        )
        is False
    )
    assert (
        decode_module._looks_like_get_assertion_request(
            {"rpId": "example.com", 2: b"hash", 3: b"signature"}
        )
        is False
    )
    assert (
        decode_module._looks_like_get_assertion_request(
            {"rpId": "example.com", 2: b"hash", "authData": b"\x00" * 37}
        )
        is False
    )


def test_interpret_get_assertion_map_handles_signature_and_trailing_field_recovery(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_format_auth_data_for_expanded_json",
        lambda _auth_data: ({"flags": {}}, b"trailing"),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_decode_trailing_map",
        lambda _trailing: {3: b"sig", 4: {1: b"u"}, 5: 2, 6: True, 8: {"ok": 1}, 9: "x"},
        raising=False,
    )

    interpreted = decode_module._interpret_get_assertion_map(
        {
            2: b"auth-data",
            4: {"name": "front-user"},
            99: "extra",
        }
    )

    assert interpreted["3 (signature)"] == b"sig".hex()
    assert interpreted["4 (user)"] == {"id": "75"}
    assert interpreted["5 (numberOfCredentials)"] == 2
    assert interpreted["6 (userSelected)"] is True
    assert interpreted["8 (extensions)"] == {"ok": 1}
    assert interpreted["trailingFields"] == {"9": "x"}
    assert interpreted["99"] == "extra"

    direct_signature = decode_module._interpret_get_assertion_map({2: b"auth", 3: b"sig"})
    assert direct_signature["3 (signature)"] == b"sig".hex()


def test_describe_authenticator_data_bytes_includes_extensions_summary_when_mapping_present():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = decode_module.AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        decode_module.AuthenticatorData.FLAG.UP | decode_module.AuthenticatorData.FLAG.ED,
        5,
        b"",
        {"credProtect": 2},
    )

    described = decode_module._describe_authenticator_data_bytes(bytes(auth_data))
    assert "extensions" in described
    assert described["extensions"]["raw"]["credProtect"] == 2
    assert described["extensions"]["summary"]["credProtectLabel"] == "userVerificationOptionalWithCredentialIDList"


def test_build_client_data_details_handles_invalid_challenge_and_optional_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    details = decode_module._build_client_data_details(
        {
            "type": "webauthn.create",
            "challenge": "not-valid-binary",
            "origin": "https://example.com",
            "crossOrigin": True,
            "tokenBinding": {"status": "present"},
        },
        raw_text="raw-json-text",
    )

    assert details["challenge"]["raw"] == "not-valid-binary"
    assert details["crossOrigin"] is True
    assert details["tokenBinding"] == {"status": "present"}
    assert details["rawText"] == "raw-json-text"

    no_challenge = decode_module._build_client_data_details({"type": "x", "origin": "https://e"})
    assert no_challenge["challenge"] is None


def test_convert_result_to_data_covers_empty_cbor_and_generic_fallback_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    cbor_payload = decode_module._convert_result_to_data("CBOR", {"decoded": {"only": "decoded"}})
    assert cbor_payload["cbor"] == {"only": "decoded"}

    cbor_non_mapping = decode_module._convert_result_to_data("CBOR", {"decoded": [1, 2, 3]})
    assert cbor_non_mapping == {"cbor": [1, 2, 3]}

    assert decode_module._convert_result_to_data("SomethingElse", {"decoded": {"x": 1}}) == {"x": 1}
    assert decode_module._convert_result_to_data("SomethingElse", {"binary": {"y": 2}}) == {"y": 2}
    assert decode_module._convert_result_to_data("SomethingElse", {}) == {}


def test_convert_certificate_bytes_and_json_block_formatting_guard_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._convert_certificate_bytes("%%") == {}

    monkeypatch.setattr(decode_module, "serialize_attestation_certificate", lambda _bytes: None, raising=False)
    assert decode_module._convert_certificate_bytes(b"\x30\x82\x01\x00") == {}

    assert decode_module._format_json_block(None) == []

    class _Unserializable:
        def __str__(self):
            return "unserializable-value"

    assert decode_module._format_json_block(_Unserializable()) == ["unserializable-value"]


def test_merge_trailing_signature_and_payload_helpers_cover_remaining_branches(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._merge_trailing_signature({}, {1: "packed", 2: b"auth"}, b"\x00\x00") is None
    assert decode_module._merge_trailing_signature({}, {1: "none", 2: b"auth"}, b"sig") is None
    assert decode_module._merge_trailing_signature({}, {1: "packed", 2: b"auth", 3: b"sig"}, b"sig") is None
    assert decode_module._merge_trailing_signature([], {1: "packed", 2: b"auth"}, b"sig") is None

    payload = decode_module._build_authenticator_data_payload(None, "not-a-map")
    assert payload == {}

    detailed_payload = decode_module._build_authenticator_data_payload(
        None,
        {
            "rpIdHash": "rp-hash",
            "flags": {},
            "signCount": "not-an-int",
            "extensions": {"uvm": True},
        },
    )
    assert detailed_payload["rpIdHash"] == "rp-hash"
    assert detailed_payload["counter"] == "not-an-int"
    assert detailed_payload["extensions"] == {"uvm": True}


def test_decode_trailing_map_handles_non_progress_and_unhashable_keys(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_lenient_decode_from",
        lambda _data, offset=0: (None, offset),
        raising=False,
    )
    assert decode_module._decode_trailing_map(b"\x01") == {}

    key_then_value = [([1], 1), ("value", 2), (None, 2)]

    def _sequence_decoder(_data, offset=0):
        _value, new_offset = key_then_value.pop(0)
        return _value, new_offset

    monkeypatch.setattr(decode_module, "_lenient_decode_from", _sequence_decoder, raising=False)
    assert decode_module._decode_trailing_map(b"\x00\x00") == {"[1]": "value"}