"""The order CTAP2 puts CBOR map keys in, for the encoder and the decoder.

CTAP 2.2, "Message Encoding", CTAP2 canonical CBOR encoding form: the keys in
every map sort lowest first, by major type, then by the length of the encoded
key, then bytewise. That is not RFC 7049's canonical order, which compares
length first: ``{24: 0, "": 0}`` is ``a2 1818 00 6000`` in CTAP2.

The encoder writes maps in this order; the decoder reports maps that are not.
"""
from __future__ import annotations


def ctap2_key_order(encoded_key: bytes) -> tuple[int, int, bytes]:
    """Sort key for one map key, given its CBOR encoding."""

    return encoded_key[0] >> 5, len(encoded_key), encoded_key
