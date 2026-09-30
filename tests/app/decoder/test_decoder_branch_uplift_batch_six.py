from __future__ import annotations

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
