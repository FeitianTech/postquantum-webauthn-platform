"""The decoder shows what was sent. It never synthesizes a field.

The repair code this replaces was written in October 2025 for the output dumps
in a since-deleted ``CBOR_hexcode.txt``. Every one of those dumps has bytes
missing -- the ES256 makeCredential dump below reads ``63 61 6c 26`` where the
authenticator sent ``"alg": -7`` (``63 61 6c 67 26``): the ``g`` is gone, so the
text string swallows the ``-7``. The repairs recognised those shapes and
invented an attStmt, an algorithm and a signature to fill them in.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from fido2 import cbor

# The "Credential Creation ES256 Output" dump from CBOR_hexcode.txt (ce03e270).
ES256_MAKE_CREDENTIAL_DUMP = (
    "00a301667061636b656402589d49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97"
    "6345000000044d41190c7beb4a8018adf265a6352d0019f785d850be6b4bd7b241c30f69efd61f5f637279707461"
    "6e65a5010203262001215820a58e44e07b296acfe3908846c7230b8887c790a19c0d75bb31d51b7a26dd1f225820"
    "225716514d192d4c5ba6496e2a66fb93e5afdf02118371099917423e88194a7103a263616c26637369675846304402"
    "2045ecc72dc3103ec407e6a6e1cd40d9c11d69d12dd1df7ef2ef8a9e71d943de0902202bcf5b7c6f8c2620764d3a9f"
    "31e4711d55358e77187abd021a366a974fc41e"
)

# The "Get Assertion ES256 Output" dump. Its rpIdHash (sha256("localhost")) has
# lost its 0x88, so authData's 37 bytes swallow the 0x03 key of the signature.
ES256_GET_ASSERTION_DUMP = (
    "00a501a2626964581911402ef9ec5f449eb8ea1d5f645a0e585f6372797074616e6564747970656a7075626c6963"
    "2d6b657902582549960de50e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976305000000040358473045"
    "022100aad84e3fddd28d95223a4c33f94245788f99f2bbfdd94c700109ffd336f2b6022062a8f2dab99c1945cfb03c"
    "ab0a77fa8e4f591389aebfbcaae22d4af126f6d1c304a36269645065fd82a31143f78f40697a0938af90646e616d65"
    "66615f757365726b646973706c61794e616d6567412e20557365720501"
)


def _decode(text: str) -> dict[str, Any]:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    return decode_module.decode_payload_text(text)


def _walk_items(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _authenticator_data() -> bytes:
    return hashlib.sha256(b"example.com").digest() + b"\x01" + (5).to_bytes(4, "big")


def test_the_es256_dump_with_a_lost_byte_is_not_given_an_att_stmt():
    result = _decode(ES256_MAKE_CREDENTIAL_DUMP)

    items = list(_walk_items(result["data"]))
    # The text key the lost byte produced is shown as it was read.
    assert ("al&", "sig") in items
    # No attestation statement, algorithm or signature is made up for it.
    assert all(item is None for key, item in items if "attStmt" in str(key))
    assert not any(key == "alg" for key, _ in items)
    assert "signatureLength" not in result["data"].get("ctap", {})
    # The 71 bytes after the map are reported, not folded into a signature.
    assert result["malformed"]


def test_a_byte_string_map_key_is_not_turned_into_an_ml_dsa_87_att_stmt():
    body = (
        b"\xa3"
        + cbor.encode(1)
        + cbor.encode("packed")
        + cbor.encode(2)
        + cbor.encode(_authenticator_data())
        + cbor.encode(b"\x99\x99\x99\x99")
        + cbor.encode(0)
    )

    result = _decode((b"\x00" + body).hex())

    items = list(_walk_items(result["data"]))
    assert all(item is None for key, item in items if "attStmt" in str(key))
    serialized = json.dumps(result)
    assert "-50" not in serialized
    assert "ML-DSA" not in serialized
    assert "99999999" in serialized


def test_bytes_after_an_attestation_object_are_never_read_as_its_signature():
    attestation_object = cbor.encode(
        {"fmt": "packed", "authData": _authenticator_data(), "attStmt": {"alg": -7, "sig": b"\x30\x06"}}
    )
    junk = bytes.fromhex("c0ffee00c0ffee")

    result = _decode((attestation_object + junk).hex())

    assert junk.hex() not in json.dumps(result["data"])
    assert result["malformed"]


def test_the_get_assertion_dump_with_a_lost_byte_is_not_given_a_signature():
    result = _decode(ES256_GET_ASSERTION_DUMP)

    items = list(_walk_items(result))
    assert not any("signature" in str(key) and item is not None for key, item in items)
    assert "signatureLength" not in result["data"].get("ctap", {})
