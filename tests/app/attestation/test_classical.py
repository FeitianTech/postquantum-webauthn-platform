"""``webauthn.attestation.classical``: an attestation's root, chain and dates, and its MDS trust.

``checks`` calls ``_evaluate_classical_attestation_root`` for a classical (not
ML-DSA) attestation; the MDS evaluation it asks for is a stand-in here, with the
outcome each test states.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import classical as attestation_classical
from server.app.webauthn.attestation import evaluation as attestation_evaluation
from tests.app.characterization import material

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
AFTER_EXPIRY = datetime(2100, 1, 1, tzinfo=timezone.utc)
LEAF = material.certificate(material.ec_key("classical-leaf").public_key(), common_name="Classical Leaf", serial=0xC1)
ROOT = material.certificate(material.ec_key("classical-root").public_key(), common_name="Classical Root", serial=0xC2)
ENTRY = SimpleNamespace(metadata_statement=SimpleNamespace())


@pytest.fixture
def evaluate(make_app, monkeypatch):
    """Evaluate ``trust_path`` against an MDS whose evaluation says ``chain_valid``, and whose
    entry's FIDO trust is ``fido_trusted``; ``mds=False`` for no MDS at all."""

    def _evaluate(trust_path, *, mds=True, chain_valid=True, fido_trusted=None, mds_errors=(), config=None, now=NOW):
        outcome = SimpleNamespace(
            trust_path=attestation_evaluation.TrustPathEvaluation(
                attestation_result=None, ca_certificate=ROOT, chain_valid=chain_valid, errors=list(mds_errors)
            ),
            metadata_entry=ENTRY,
            metadata_lookup_source="aaguid",
        )
        monkeypatch.setattr(attestation_evaluation, "evaluate_attestation", lambda *_args: outcome)
        monkeypatch.setattr(mds_verifier, "metadata_entry_trust_anchor_status", lambda _entry: fido_trusted)
        with make_app(config or {}).app_context():
            return attestation_classical._evaluate_classical_attestation_root(
                SimpleNamespace(att_stmt={}),
                SimpleNamespace(trust_path=trust_path),
                b"client-data-hash",
                verifier=object() if mds else None,
                now=now,
            )

    return _evaluate


def test_without_a_trust_path_or_metadata_nothing_is_trusted(evaluate):
    outcome = evaluate([], mds=False)

    assert outcome["errors"] == ["trust_path_missing"]
    assert outcome["warnings"] == ["metadata_not_available"]
    assert outcome["checks"] == {"trusted_ca": False, "chain": None, "fido_mds": None}
    assert outcome["root_valid"] is None


def test_a_root_the_mds_trusts_makes_the_attestation_valid(evaluate):
    outcome = evaluate([LEAF], fido_trusted=True)

    assert outcome["checks"] == {"trusted_ca": True, "chain": True, "fido_mds": True}
    assert outcome["root_valid"] is True
    assert outcome["metadata_lookup_source"] == "aaguid"


def test_an_expired_leaf_makes_the_chain_invalid_and_an_untrusted_entry_is_reported(evaluate):
    outcome = evaluate([LEAF], fido_trusted=False, now=AFTER_EXPIRY)

    assert outcome["errors"] == [
        "certificate_out_of_validity: CN=Classical Leaf,OU=Authenticator Attestation,O=Characterization Test,C=SE",
        "metadata_not_fido_trusted",
    ]
    assert outcome["checks"] == {"trusted_ca": True, "chain": False, "fido_mds": False}
    assert outcome["root_valid"] is False


def test_a_root_the_operator_does_not_trust_is_reported_beside_the_mds_errors(evaluate):
    config = {"TRUSTED_ATTESTATION_CA_FINGERPRINTS": {hashlib.sha256(b"another root").hexdigest().upper()}}

    outcome = evaluate([LEAF], mds_errors=["mds_chain_warning"], config=config)

    assert outcome["errors"] == ["mds_chain_warning", "attestation_root_not_trusted"]
    assert outcome["checks"]["trusted_ca"] is False
    assert outcome["checks"]["chain"] is None


def test_a_chain_whose_leaf_the_next_certificate_did_not_issue_does_not_verify(evaluate):
    # The MDS gives no verdict of its own, so the chain's own signatures decide.
    outcome = evaluate([LEAF, ROOT], chain_valid=None)

    assert outcome["checks"]["chain"] is False


def test_bytes_in_a_trust_path_that_are_not_a_certificate_are_reported(evaluate):
    outcome = evaluate([b"not a certificate"], chain_valid=None)

    assert [error.split(":")[0] for error in outcome["errors"]] == ["certificate_chain_error", "certificate_parse_error"]
    assert outcome["checks"]["chain"] is False
