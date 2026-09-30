"""``webauthn.attestation.certificate_names``: how the certificate views spell names and algorithms."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from server.app.webauthn.attestation import (
    certificate_names as attestation_certificate_names,
)


def test_a_name_is_spelled_in_rfc4514_and_otherwise_as_its_string():
    class NameWithoutRfc4514:
        def rfc4514_string(self):
            raise ValueError("cannot format")

        def __str__(self):
            return "the name as a string"

    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.COMMON_NAME, "Demo CN")])

    assert attestation_certificate_names.format_x509_name(name) == "CN=Demo CN,C=US"
    assert attestation_certificate_names.format_x509_name(NameWithoutRfc4514()) == "the name as a string"


def test_common_names_are_the_non_blank_text_ones():
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, " Demo CN "),
            x509.NameAttribute(NameOID.COMMON_NAME, " "),
        ]
    )
    not_text = SimpleNamespace(get_attributes_for_oid=lambda _oid: [SimpleNamespace(value=b"bytes")])

    assert attestation_certificate_names._extract_common_names(name) == ["Demo CN"]
    assert attestation_certificate_names._extract_common_names(not_text) == []


@pytest.mark.parametrize(
    ("signature", "info"),
    [
        ({"algorithm": "ecdsa", "hash": "sha-256"}, "ECDSA_SHA256"),
        ({"algorithm": "ed448"}, "ED448_SHAKE256"),
        ("not-a-mapping", ""),
    ],
)
def test_the_algorithm_info_joins_the_algorithm_and_its_hash(signature, info):
    assert attestation_certificate_names._derive_certificate_algorithm_info(signature) == info
