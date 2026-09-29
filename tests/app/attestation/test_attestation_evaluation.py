"""``attestation.evaluation``: each step of checking an attestation against FIDO metadata.

The metadata and the registrations are the MDS characterization record's (a
P-256 root that signed the attestation certificate, one of the same name with
another key, an entry found by key identifier); the tests here reach the steps
that record does not show on its own.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography import x509

from fido2.attestation import UnsupportedType
from fido2.mds3 import MdsAttestationVerifier, MetadataBlobPayload
from fido2.webauthn import RegistrationResponse
from server.app.webauthn.attestation import evaluation
from tests.app.characterization import material
from tests.app.characterization import (
    test_attestation_mds_characterization as mds_record,
)
from tests.app.metadata import mds_fixture


def _attestation(name: str):
    registration = RegistrationResponse.from_dict(mds_record._cases()[name])
    client_data = registration.response.client_data
    return registration.response.attestation_object, hashlib.sha256(client_data).digest()


def _evaluate(name: str, verifier=None) -> evaluation.MdsEvaluation:
    attestation_object, client_data_hash = _attestation(name)
    return evaluation.evaluate_attestation(verifier or mds_record._verifier(), attestation_object, client_data_hash)


def _verifier_with(*, roots: list[bytes], status_reports: list[dict] | None = None) -> MdsAttestationVerifier:
    template = json.loads(mds_fixture.CUSTOM_METADATA_PATH.read_text(encoding="utf-8"))["entries"][0]
    entry = mds_record._entry(template, aaguid=mds_record.AAGUID, roots=roots)
    if status_reports is not None:
        entry["statusReports"] = status_reports
    payload = {"legalHeader": "Evaluation metadata", "no": 1, "nextUpdate": "2099-12-31", "entries": [entry]}
    return MdsAttestationVerifier(MetadataBlobPayload.from_dict(payload))


def test_a_trust_path_that_ends_in_the_entrys_root_verifies():
    outcome = _evaluate("x5c-listed")

    assert outcome.trust_path.errors == []
    assert outcome.trust_path.chain_valid is True
    assert outcome.trust_path.ca_certificate == mds_record._root("mds-root")
    assert outcome.metadata_entry.metadata_statement.description == f"Characterization {mds_record.AAGUID.hex()}"
    assert outcome.metadata_lookup_source == "aaguid"


def test_a_root_of_the_same_name_with_another_key_does_not():
    outcome = _evaluate("x5c-wrong-root")

    assert outcome.trust_path.chain_valid is False
    assert outcome.trust_path.errors == [""]
    assert outcome.metadata_lookup_source == "aaguid"


def test_an_authenticator_without_an_aaguid_is_found_by_key_identifier():
    outcome = _evaluate("x5c-by-key-identifier")

    assert outcome.trust_path.chain_valid is True
    assert outcome.metadata_lookup_source == "chain"


def test_an_authenticator_the_metadata_does_not_list_has_no_root():
    outcome = _evaluate("x5c-unlisted")

    assert outcome.trust_path.errors == ["No root found for Authenticator"]
    assert outcome.metadata_entry is None
    assert outcome.metadata_lookup_source is None


def test_a_trust_path_issued_by_a_root_the_entry_does_not_list_has_no_root():
    # Issued by the characterization CA, whose name no root of the entry has.
    outcome = _evaluate("x5c-listed-ed25519-ca")

    assert outcome.trust_path.errors == ["No root found for Authenticator"]
    assert outcome.metadata_entry is None
    assert outcome.metadata_lookup_source == "aaguid"


def test_the_none_format_is_not_one_metadata_can_vouch_for():
    with pytest.raises(UnsupportedType, match='Attestation format "none" is not supported'):
        _evaluate("none-listed")


def test_a_statement_that_does_not_verify_stops_before_the_metadata():
    outcome = _evaluate("x5c-listed-tampered")

    assert outcome.trust_path.attestation_result is None
    assert outcome.trust_path.chain_valid is False
    assert len(outcome.trust_path.errors) == 1
    assert (outcome.metadata_entry, outcome.metadata_lookup_source) == (None, None)


def test_a_lookup_that_fails_is_reported_as_an_error():
    class _Unreachable:
        def find_entry_by_aaguid(self, _aaguid):
            raise RuntimeError("metadata unreachable")

    outcome = _evaluate("x5c-listed", _Unreachable())

    assert outcome.trust_path.errors == ["metadata unreachable"]
    assert outcome.trust_path.attestation_result is not None
    assert outcome.metadata_lookup_source is None


def test_roots_that_do_not_parse_are_passed_over():
    verifier = _verifier_with(roots=[b"not a certificate", mds_record._root("mds-root")])

    outcome = _evaluate("x5c-listed", verifier)

    assert outcome.trust_path.chain_valid is True
    assert outcome.trust_path.ca_certificate == mds_record._root("mds-root")


def test_a_compromised_attestation_key_gets_no_root():
    leaf = mds_record._leaf(mds_record.AAGUID)
    report = {
        "status": "ATTESTATION_KEY_COMPROMISE",
        "effectiveDate": "2024-01-01",
        "certificate": base64.b64encode(leaf).decode(),
    }
    verifier = _verifier_with(roots=[mds_record._root("mds-root")], status_reports=[report])

    outcome = _evaluate("x5c-listed", verifier)

    assert outcome.trust_path.errors == ["No root found for Authenticator"]
    assert outcome.metadata_entry is None
    assert outcome.metadata_lookup_source == "aaguid"


def test_a_self_attestation_gets_no_root_even_when_its_aaguid_is_listed():
    """Nothing but the credential's own key signed it; a root of the entry vouches for nothing here."""

    outcome = _evaluate("self-listed")

    assert outcome.trust_path.errors == ["No root found for Authenticator"]
    assert outcome.trust_path.ca_certificate is None
    assert outcome.trust_path.chain_valid is False
    assert outcome.metadata_entry is None
    assert outcome.metadata_lookup_source == "aaguid"


def test_the_record_and_these_tests_share_one_attestation_certificate():
    # _leaf is material's attestation certificate issued by another root: same key.
    leaf = x509.load_der_x509_certificate(mds_record._leaf(mds_record.AAGUID))
    material_leaf = x509.load_der_x509_certificate(material.attestation_leaf_certificate(mds_record.AAGUID))
    assert leaf.public_key() == material_leaf.public_key()
