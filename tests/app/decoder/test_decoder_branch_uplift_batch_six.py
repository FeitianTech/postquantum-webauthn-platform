from __future__ import annotations

import hashlib

import cbor2
import pytest

from fido2.webauthn import AuthenticatorData


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


def test_interpret_get_assertion_map_leaves_a_missing_signature_missing(monkeypatch, ctap):
    # Bytes left over inside authData are not read as the response's missing
    # members: the signature stays missing and nothing else is added.
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # The tail is the CBOR of {3: h'736967', 5: 2, 9: "x"} without its map
    # header: what the old repair read back as a signature and members.
    tail = cbor2.dumps(3) + cbor2.dumps(b"sig") + cbor2.dumps(5) + cbor2.dumps(2) + cbor2.dumps(9) + cbor2.dumps("x")
    monkeypatch.setattr(
        ctap,
        "_format_auth_data_for_expanded_json",
        lambda _auth_data: ({"flags": {}}, tail),
    )

    interpreted = decode_module._interpret_get_assertion_map(
        {
            2: b"auth-data",
            4: {"name": "front-user"},
            99: "extra",
        }
    )

    assert interpreted["3 (signature)"] is None
    assert interpreted["4 (user)"] == {"name": "front-user"}
    assert interpreted["99"] == "extra"
    assert "trailingFields" not in interpreted
    assert "5 (numberOfCredentials)" not in interpreted

    direct_signature = decode_module._interpret_get_assertion_map({2: b"auth", 3: b"sig"})
    assert direct_signature["3 (signature)"] == b"sig".hex()


def test_describe_authenticator_data_bytes_includes_extensions_summary_when_mapping_present():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.ED,
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


def test_convert_certificate_bytes_and_json_block_formatting_guard_paths(monkeypatch, response):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._convert_certificate_bytes("%%") == {}

    monkeypatch.setattr(response, "serialize_attestation_certificate", lambda _bytes: None)
    assert decode_module._convert_certificate_bytes(b"\x30\x82\x01\x00") == {}

    assert decode_module._format_json_block(None) == []

    class _Unserializable:
        def __str__(self):
            return "unserializable-value"

    assert decode_module._format_json_block(_Unserializable()) == ["unserializable-value"]


def test_build_authenticator_data_payload_covers_non_mapping_and_partial_details():
    decode_module = pytest.importorskip("server.app.decoder.decode")

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
