"""One CTAP2 map key order, read by the encoder and the canonical-form check."""
from __future__ import annotations

from server.app.decoder import cbor_canonical, ctap2_order


def test_keys_sort_by_major_type_then_encoded_length_then_bytes():
    # 24 (1818), -1 (20), h'' (40), "" (60), "a" (6161), "b" (6162)
    encoded = [bytes.fromhex(h) for h in ("6162", "60", "40", "20", "1818", "6161", "05")]

    ordered = sorted(encoded, key=ctap2_order.ctap2_key_order)

    assert [key.hex() for key in ordered] == ["05", "1818", "20", "40", "60", "6161", "6162"]


def test_the_encoder_sorts_with_the_same_rule():
    assert cbor_canonical.ctap2_key_order is ctap2_order.ctap2_key_order
