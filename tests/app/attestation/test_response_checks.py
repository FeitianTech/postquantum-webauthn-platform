"""``webauthn.attestation.response_checks``: what a registration response says against what was expected.

The response's own checks run in every registration (``test_checks.py``, the
attestation-checks golden); these are what only a direct call reaches.
"""
from __future__ import annotations

import pytest

from server.app.webauthn.attestation import response_checks
from tests.app import fido2_stand_ins as stand_ins

# What fido2 never hands over -- a credential ID without a length, a public key it
# did not parse, an AAGUID that is not bytes -- only a direct call reaches.


class _UnreadableKey:
    def __iter__(self):
        raise TypeError("cannot iterate")

    def get(self, _label):
        raise RuntimeError("cannot read alg")


class _KeyWithOnlyAnAlgorithm(dict):
    def __iter__(self):
        return iter(())

    def get(self, label, default=None):
        return -7 if label == 3 else default


@pytest.mark.parametrize(
    ("public_key", "algorithm"),
    [({}, None), (_UnreadableKey(), None), (_KeyWithOnlyAnAlgorithm(), -7)],
)
def test_credential_facts_report_a_public_key_that_does_not_parse(public_key, algorithm):
    results = {"errors": []}
    credential = stand_ins.CredentialData(credential_id=123, public_key=public_key, aaguid=object())

    facts = response_checks._credential_facts(results, credential)

    assert facts["credential_id_length"] is None
    assert (facts["credential_aaguid"], facts["credential_aaguid_bytes"]) == (None, b"")
    assert facts["algorithm"] == algorithm
    assert facts["cose_key_valid"] is False
    assert [error.split(":")[0] for error in results["errors"]] == ["cose_key_error"]


def test_credential_facts_report_a_key_that_reads_but_cannot_be_used():
    results = {"errors": []}
    off_curve = {**stand_ins.ES256_KEY, -2: b"\x01" * 32, -3: b"\x02" * 32}

    facts = response_checks._credential_facts(results, stand_ins.CredentialData(public_key=off_curve))

    assert (facts["algorithm"], facts["cose_key_valid"]) == (-7, False)
    assert results["errors"] == ["cose_key_invalid: the point is not on P-256"]


def test_credential_facts_find_a_key_on_its_curve_valid():
    results = {"errors": []}

    facts = response_checks._credential_facts(results, stand_ins.CredentialData())

    assert (facts["algorithm"], facts["cose_key_valid"], results["errors"]) == (-7, True, [])
