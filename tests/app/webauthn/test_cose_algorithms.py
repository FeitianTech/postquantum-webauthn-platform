"""``webauthn.cose_algorithms``: a COSE algorithm a client names, as its number."""
from __future__ import annotations

import pytest

from server.app.webauthn import cose_algorithms


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-7, -7),
        (-7.0, -7),
        ("-257", -257),
        (" -8 ", -8),
        ("ES256", -7),
        ("FIDO_ALG_ES256", -7),
        ("COSE_ALG_EDDSA", -8),
        ("Experimental ML-DSA-65", -49),
        # What is in parentheses is a comment on the name.
        ("ES256 (ECDSA)", -7),
        # No name it knows: the last number in the text.
        ("fido custom alg (-12345)", -12345),
    ],
)
def test_an_algorithm_is_read_from_a_number_or_a_name(value, expected):
    assert cose_algorithms.coerce_cose_algorithm(value) == expected


@pytest.mark.parametrize(
    "value",
    [True, 1.5, float("inf"), float("-inf"), float("nan"), "", "   ", "no number here", [-7], None],
)
def test_what_names_no_algorithm_is_none(value):
    assert cose_algorithms.coerce_cose_algorithm(value) is None


@pytest.mark.parametrize("name", ["", "   ", "(ES256)"])
def test_a_blank_name_names_no_algorithm(name):
    assert cose_algorithms.lookup_name(name) is None
