"""``webauthn.signature_algorithms``: the one spelling of a certificate's signature algorithm."""
from __future__ import annotations

import pytest

from server.app.webauthn import signature_algorithms


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("RSASSA-PSS with SHA-256", "RSASSA-PSS"),
        ("rsassaPss", "RSASSA-PSS"),
        ("rsassa_pss", "RSASSA-PSS"),
        ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
        ("sha256WithRSAEncryption", "RSASSA-PKCS1-v1_5"),
        ("2.16.840.1.101.3.4.3.16", "RSASSA-PKCS1-v1_5"),
        ("ML-DSA-87", "ML-DSA-87"),
        ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
        ("2.16.840.1.101.3.4.3.12", "ECDSA"),
        ("ed448 with shake", "ED448"),
        ("dsa-with-sha1", "DSA"),
        ("custom algo", "CUSTOMALGO"),
        ("some thing-else", "SOMETHINGELSE"),
        ("", ""),
    ],
)
def test_a_signature_algorithm_is_named_without_its_hash_by_name_or_oid(name, expected):
    assert signature_algorithms.normalise_signature_algorithm_name(name) == expected


@pytest.mark.parametrize(("value", "expected"), [(" RSASSA PSS ", "RSASSAPSS"), ("—", ""), ("", ""), (None, "")])
def test_an_algorithm_component_drops_its_spaces_and_a_dash_stands_for_none(value, expected):
    assert signature_algorithms.format_algorithm_component(value) == expected
