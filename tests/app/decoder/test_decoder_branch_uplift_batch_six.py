from __future__ import annotations

import hashlib

from fido2.webauthn import AuthenticatorData

from server.app.decoder.decode import answer as decode_answer
from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import certificates as decode_certificates
from server.app.decoder.decode import credential_json
from server.app.decoder.decode import ctap_classify as decode_ctap_classify
from server.app.webauthn.attestation import certificates as attestation_certificates


def test_looks_like_get_assertion_request_rejects_signature_or_authdata_binary_shapes():
    assert decode_ctap_classify._looks_like_get_assertion_request("not-a-map") is False
    assert (
        decode_ctap_classify._looks_like_get_assertion_request(
            {"rpId": "example.com", "clientDataHash": "not-binary"}
        )
        is False
    )
    assert (
        decode_ctap_classify._looks_like_get_assertion_request(
            {"rpId": "example.com", 2: b"hash", 3: b"signature"}
        )
        is False
    )
    assert (
        decode_ctap_classify._looks_like_get_assertion_request(
            {"rpId": "example.com", 2: b"hash", "authData": b"\x00" * 37}
        )
        is False
    )


def test_describe_authenticator_data_bytes_includes_extensions_summary_when_mapping_present():
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.ED,
        5,
        b"",
        {"credProtect": 2},
    )

    described = decode_authenticator_data._describe_authenticator_data_bytes(bytes(auth_data))
    assert "extensions" in described
    assert described["extensions"]["raw"]["credProtect"] == 2
    assert described["extensions"]["summary"]["credProtectLabel"] == "userVerificationOptionalWithCredentialIDList"


def test_build_client_data_details_handles_invalid_challenge_and_optional_fields():
    details = credential_json.build_client_data_details(
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

    no_challenge = credential_json.build_client_data_details({"type": "x", "origin": "https://e"})
    assert no_challenge["challenge"] is None


def test_convert_result_to_data_covers_empty_cbor_and_generic_fallback_paths():
    cbor_payload = decode_answer._convert_result_to_data("CBOR", {"decoded": {"only": "decoded"}})
    assert cbor_payload["cbor"] == {"only": "decoded"}

    cbor_non_mapping = decode_answer._convert_result_to_data("CBOR", {"decoded": [1, 2, 3]})
    assert cbor_non_mapping == {"cbor": [1, 2, 3]}

    assert decode_answer._convert_result_to_data("SomethingElse", {"decoded": {"x": 1}}) == {"x": 1}
    assert decode_answer._convert_result_to_data("SomethingElse", {"binary": {"y": 2}}) == {"y": 2}
    assert decode_answer._convert_result_to_data("SomethingElse", {}) == {}


def test_convert_certificate_bytes_guard_paths(monkeypatch):
    assert decode_certificates.convert_certificate_bytes("%%") == {}

    monkeypatch.setattr(attestation_certificates, "serialize_attestation_certificate", lambda _bytes: None)
    assert decode_certificates.convert_certificate_bytes(b"\x30\x82\x01\x00") == {}


def test_build_authenticator_data_payload_covers_non_mapping_and_partial_details():
    payload = decode_answer._build_authenticator_data_payload(None, "not-a-map")
    assert payload == {}

    detailed_payload = decode_answer._build_authenticator_data_payload(
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
