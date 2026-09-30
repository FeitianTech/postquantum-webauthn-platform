"""``webauthn.attestation.checks``: what a registration's attestation checks report.

The response is read from fido2 stand-ins (``tests/app/fido2_stand_ins.py``):
``RegistrationResponse.from_dict`` is patched to hand them over, so each test
states one thing a client could send and what the checks say of it.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fido2.attestation import Attestation
from fido2.webauthn import AuthenticatorData, RegistrationResponse

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import checks as attestation_checks
from tests.app import fido2_stand_ins as stand_ins
from tests.app.security.ceremony_helpers import b64u

CHALLENGE = b"the-challenge"
ES256_ONLY = {"pubKeyCredParams": [{"alg": -7}]}


@pytest.fixture
def check(monkeypatch):
    """Run the checks over a response the stand-ins make, with ``verifier`` as the MDS."""

    def _check(*, state, options=ES256_ONLY, client_data=None, attestation=None, verifier=None):
        registration = stand_ins.registration(
            attestation or stand_ins.attestation_object(),
            client_data or stand_ins.ClientData(challenge=CHALLENGE),
        )
        monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _response: registration)
        monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: verifier)
        return attestation_checks.perform_attestation_checks(
            response={"stand-in": True},
            state=state,
            public_key_options=options,
            auth_data=None,
            expected_origin="https://example.com/",
            rp_id="example.com",
        )

    return _check


def test_a_response_that_is_not_a_mapping_is_invalid():
    result = attestation_checks.perform_attestation_checks(
        response=["not-a-mapping"],
        state=None,
        public_key_options=None,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["errors"] == ["registration_response_invalid"]


@pytest.mark.parametrize(
    ("state", "options"),
    [
        ({"challenge": {"$base64url": b64u(CHALLENGE)}}, ES256_ONLY),
        # Text in no binary alphabet is the challenge's UTF-8.
        ({"challenge": CHALLENGE.decode("ascii")}, ES256_ONLY),
        # A wrapper the state cannot read leaves the challenge to the options.
        ({"challenge": {"$base64": "%%%"}}, {**ES256_ONLY, "challenge": {"$hex": CHALLENGE.hex()}}),
        ({"challenge": {"$hex": "zz"}}, {**ES256_ONLY, "challenge": CHALLENGE}),
        (None, {**ES256_ONLY, "challenge": {"$base64": b64u(CHALLENGE).replace("-", "+").replace("_", "/") + "="}}),
    ],
)
def test_the_expected_challenge_is_read_from_the_state_or_else_the_options(check, state, options):
    result = check(state=state, options=options)

    assert result["client_data"]["expected_challenge"] == b64u(CHALLENGE)
    assert result["client_data"]["challenge_matches"] is True
    assert "challenge_mismatch" not in result["errors"]


@pytest.mark.parametrize(
    "challenge",
    [None, {"$base64": 5}, {"$hex": 7}, {"$base64": "%%%"}, {"unexpected": True}, 12345],
)
def test_without_a_readable_expected_challenge_none_is_compared(check, challenge):
    result = check(state={"challenge": challenge}, options={**ES256_ONLY, "challenge": challenge})

    assert result["client_data"]["expected_challenge"] is None
    assert result["client_data"]["challenge_matches"] is False
    assert "challenge_mismatch" not in result["errors"]


@pytest.mark.parametrize(
    ("state", "options"),
    [
        ({"challenge": CHALLENGE, "user_verification": SimpleNamespace(value="required")}, ES256_ONLY),
        ({"challenge": CHALLENGE}, {**ES256_ONLY, "authenticatorSelection": {"userVerification": "required"}}),
    ],
)
def test_user_verification_the_ceremony_required_must_be_performed(check, state, options):
    verified = stand_ins.AuthData(flags=stand_ins.UP_AT | int(AuthenticatorData.FLAG.UV))

    satisfied = check(state=state, options=options, attestation=stand_ins.attestation_object(auth_data=verified))
    missing = check(state=state, options=options)

    assert satisfied["authenticator_data"]["user_verification_required"] is True
    assert satisfied["authenticator_data"]["user_verification_satisfied"] is True
    assert missing["authenticator_data"]["user_verification_satisfied"] is False
    assert "user_verification_required_not_satisfied" in missing["errors"]


def test_without_attested_credential_data_there_is_no_credential_to_allow(check):
    bare = stand_ins.AuthData(flags=int(AuthenticatorData.FLAG.UP), credential_data=None)

    result = check(state={"challenge": CHALLENGE}, attestation=stand_ins.attestation_object(auth_data=bare))

    facts = result["authenticator_data"]
    assert (facts["credential_id_length"], facts["credential_aaguid"], facts["algorithm"]) == (None, None, None)
    assert facts["algorithm_allowed"] is False
    assert {"attested_credential_data_missing", "algorithm_not_allowed"} <= set(result["errors"])


def test_a_cose_key_whose_algorithm_is_not_a_number_is_not_an_allowed_algorithm(check):
    credential = stand_ins.CredentialData(public_key={**stand_ins.ES256_KEY, 3: "ES256"})
    attestation = stand_ins.attestation_object(auth_data=stand_ins.AuthData(credential_data=credential))

    result = check(state={"challenge": CHALLENGE}, attestation=attestation)

    assert result["authenticator_data"]["algorithm"] == "ES256"
    assert result["authenticator_data"]["algorithm_allowed"] is False
    assert "algorithm_not_allowed" in result["errors"]


def test_metadata_found_by_the_credentials_aaguid_is_reported(check):
    entry = SimpleNamespace(
        metadata_statement={"attestationRootCertificates": "a-root"},
        aaguid="00112233-4455-6677-8899-aabbccddeeff",
    )
    verifier = SimpleNamespace(find_entry_by_aaguid=lambda _aaguid: entry)

    metadata = check(state={"challenge": CHALLENGE}, verifier=verifier)["metadata"]

    assert metadata["available"] is True
    assert metadata["source"] == "aaguid"
    assert metadata["root_certificates_present"] is True
    assert metadata["aaguid"] == "00112233-4455-6677-8899-aabbccddeeff"


def test_a_metadata_lookup_that_fails_leaves_metadata_unavailable(check):
    def _unreachable(_aaguid):
        raise RuntimeError("lookup failure")

    metadata = check(state={"challenge": CHALLENGE}, verifier=SimpleNamespace(find_entry_by_aaguid=_unreachable))["metadata"]

    assert metadata["available"] is False


def test_an_attestation_statement_fido2_cannot_read_is_invalid(check):
    result = check(state={"challenge": CHALLENGE}, attestation=stand_ins.attestation_object(fmt="packed"))

    assert result["signature_valid"] is False
    assert any(error.startswith("attestation_invalid:") for error in result["errors"])


def test_a_verifier_that_fails_unexpectedly_is_an_attestation_error(check, monkeypatch):
    class _FailingVerifier:
        def verify(self, _att_stmt, _auth_data, _client_data_hash):
            raise RuntimeError("boom")

    monkeypatch.setattr(Attestation, "for_type", lambda _fmt: _FailingVerifier)

    result = check(state={"challenge": CHALLENGE}, attestation=stand_ins.attestation_object(fmt="packed"))

    assert result["signature_valid"] is False
    assert "attestation_error: boom" in result["errors"]


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

    facts = attestation_checks._credential_facts(results, credential)

    assert facts["credential_id_length"] is None
    assert (facts["credential_aaguid"], facts["credential_aaguid_bytes"]) == (None, b"")
    assert facts["algorithm"] == algorithm
    assert facts["cose_key_valid"] is False
    assert [error.split(":")[0] for error in results["errors"]] == ["cose_key_error"]
