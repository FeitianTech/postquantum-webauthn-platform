from __future__ import annotations

import hashlib

from fido2.webauthn import AuthenticatorData

from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import ctap_classify as decode_ctap_classify


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
