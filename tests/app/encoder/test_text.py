"""Tests of text behavior."""

import json

from server.app.decoder.encode import text as encode_text


def test_encode_payload_text_cbor_is_deterministic_across_equivalent_permutations():
    variants = [
        json.dumps(
            {
                "z": 1,
                "nested": {"b": 2, "a": 1},
                "k": [3, {"y": 2, "x": 1}],
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
            }
        ),
        json.dumps(
            {
                "blob": {"beta": {"n": None, "m": True}, "alpha": [1, 2]},
                "k": [3, {"x": 1, "y": 2}],
                "nested": {"a": 1, "b": 2},
                "z": 1,
            }
        ),
        json.dumps(
            {
                "nested": {"a": 1, "b": 2},
                "z": 1,
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
                "k": [3, {"x": 1, "y": 2}],
            }
        ),
    ]

    encoded_hex_values = [
        encode_text.encode_payload_text(payload, "cbor")["data"]["binary"]["hex"]
        for payload in variants
    ]

    assert len(set(encoded_hex_values)) == 1
