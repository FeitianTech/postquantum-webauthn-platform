"""``webauthn.signature_algorithms``: the one spelling of a certificate's signature algorithm."""
from __future__ import annotations

import pytest

from server.app.webauthn import signature_algorithms


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("RSASSA-PSS with SHA-256", "RSASSA-PSS"),
        ("ed448 with shake", "ED448"),
        ("dsa-with-sha1", "DSA"),
        ("custom algo", "CUSTOMALGO"),
        ("", ""),
    ],
)
def test_a_signature_algorithm_is_named_without_its_hash(name, expected):
    assert signature_algorithms.normalise_signature_algorithm_name(name) == expected


@pytest.mark.parametrize(("value", "expected"), [(" RSASSA PSS ", "RSASSAPSS"), ("—", ""), ("", ""), (None, "")])
def test_an_algorithm_component_drops_its_spaces_and_a_dash_stands_for_none(value, expected):
    assert signature_algorithms.format_algorithm_component(value) == expected
