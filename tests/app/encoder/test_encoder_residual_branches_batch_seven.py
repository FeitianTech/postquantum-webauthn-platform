from __future__ import annotations

from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_cbor_value_never_reads_a_plain_map_as_ctap():
    # A root map with CTAP member names was read as a makeCredential response.

    payload = {
        "fmt": "none",
        "authData": b"\x00" * 37,
    }

    encoded = encode_handlers_cbor._encode_cbor_value(payload)

    assert encoded["success"] is True
    assert encoded["type"] == "CBOR (canonical) (encoded)"
    assert "ctapDecoded" not in encoded["data"]
    assert encoded["data"]["binary"]["hex"].startswith("a263666d74646e6f6e65")
