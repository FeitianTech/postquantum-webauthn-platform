"""``decoder.decode.cose_display``: a COSE key as the decoder's answer shows it, and its algorithm's name."""
from __future__ import annotations

import pytest

from server.app.decoder.decode import cose_display


@pytest.mark.parametrize(
    ("key", "fallback", "name"),
    [
        ({"3": "-257"}, None, "RS256 (RSA)"),
        ({"alg": "custom-alg"}, None, "custom-alg"),
        ({}, {"publicKeyAlgorithm": -259}, "RS512 (RSA)"),
        ({}, -999, "COSE alg -999"),
        ({}, None, None),
    ],
)
def test_a_keys_algorithm_is_named_from_the_key_or_else_the_credential(key, fallback, name):
    assert cose_display._resolve_cose_algorithm(key, fallback) == name


def test_base64_values_in_a_key_are_shown_as_hex_and_anything_else_as_given():
    assert cose_display._convert_cose_key_for_display(["AQI=", {"k": "AQI="}, "not-base64$$"]) == ["0102", {"k": "0102"}, "not-base64$$"]


@pytest.mark.parametrize(("text", "value"), [("++8", b"\xfb\xef"), ("   ", None)])
def test_a_base64_field_is_read_strictly_and_a_blank_one_is_none(text, value):
    assert cose_display._decode_base64_field(text) == value
