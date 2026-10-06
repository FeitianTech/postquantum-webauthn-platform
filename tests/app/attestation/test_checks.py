"""``webauthn.attestation.checks``: what a registration's attestation checks report.

The response is read from fido2 stand-ins (``tests/app/fido2_stand_ins.py``):
``RegistrationResponse.from_dict`` is patched to hand them over, so each test
states one thing a client could send and what the checks say of it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fido2.attestation import (
    Attestation,
    AttestationResult,
    AttestationType,
    InvalidSignature,
)
from fido2.webauthn import Aaguid, AuthenticatorData, RegistrationResponse

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import checks as attestation_checks
from server.app.webauthn.attestation import evaluation
from tests.app import fido2_stand_ins
from tests.app import fido2_stand_ins as stand_ins
from tests.app.entry_app import entry_app
from tests.app.fido2_stand_ins import AuthData, ClientData
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


def _perform_checks(response, state, public_key_options, rp_id="example.com"):
    return attestation_checks.perform_attestation_checks(
        response=response,
        state=state,
        public_key_options=public_key_options,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id=rp_id,
    )


def test_perform_attestation_checks_unsupported_format_sets_signature_and_root_failure(monkeypatch):
    challenge = b"challenge"
    rp_id = "example.com"
    auth_data = AuthData(rp_id=rp_id, flags=AuthData.FLAG.UP | AuthData.FLAG.UV | AuthData.FLAG.AT)
    client_data = ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "vendor-unknown",
            "auth_data": auth_data,
            "att_stmt": {},
        },
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    result = _perform_checks(
        response={"raw": "value"},
        state={"challenge": b64u(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is False
    assert result["root_valid"] is False
    assert "attestation_signature_invalid" in result["errors"]
    assert any(error.startswith("unsupported_attestation:") for error in result["errors"])


def test_perform_attestation_checks_warns_when_metadata_verifier_unavailable(monkeypatch):
    challenge = b"metadata-unavailable"
    rp_id = "example.com"
    auth_data = AuthData(rp_id=rp_id, flags=AuthData.FLAG.UP | AuthData.FLAG.UV | AuthData.FLAG.AT)
    client_data = ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"sig": b"signature"},
        },
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    class _PassingAttestation:
        def verify(self, *_args, **_kwargs):
            return AttestationResult(AttestationType.BASIC, [])

    monkeypatch.setattr(Attestation, "for_type", lambda _fmt: _PassingAttestation)
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: None)

    result = _perform_checks(
        response={"raw": "value"},
        state={"challenge": b64u(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is True
    assert result["root_valid"] is None
    assert "metadata_not_available" in result["warnings"]
    assert "trust_path_missing" in result["errors"]


def test_perform_attestation_checks_flags_algorithm_not_in_metadata_when_root_is_valid(monkeypatch):
    challenge = b"metadata-algorithm"
    rp_id = "example.com"
    auth_data = AuthData(rp_id=rp_id, flags=AuthData.FLAG.UP | AuthData.FLAG.UV | AuthData.FLAG.AT)
    client_data = ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"sig": b"signature"},
        },
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    class _PassingAttestation:
        def verify(self, *_args, **_kwargs):
            return AttestationResult(AttestationType.BASIC, [])

    trust_path = evaluation.TrustPathEvaluation(
        attestation_result=None,
        ca_certificate=b"trusted-ca",
        chain_valid=True,
        errors=[],
    )

    metadata_statement = type(
        "_MetadataStatement",
        (),
        {
            "description": "Demo authenticator",
            "authenticator_get_info": {"algorithms": [-257]},
            "attestation_root_certificates": [b"trusted-ca"],
        },
    )()
    metadata_entry = type(
        "_MetadataEntry",
        (),
        {
            "metadata_statement": metadata_statement,
            "aaguid": Aaguid.fromhex("00112233445566778899aabbccddeeff"),
        },
    )()

    outcome = evaluation.MdsEvaluation(trust_path, metadata_entry, "aaguid")

    monkeypatch.setattr(Attestation, "for_type", lambda _fmt: _PassingAttestation)
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: object())
    monkeypatch.setattr(evaluation, "evaluate_attestation", lambda *_args, **_kwargs: outcome)

    # The trusted-CA allowlist is read from the current app.
    with entry_app().app_context():
        result = _perform_checks(
            response={"raw": "value"},
            state={"challenge": b64u(challenge), "user_verification": "required"},
            public_key_options={"pubKeyCredParams": [{"alg": -7}]},
            rp_id=rp_id,
        )

    assert result["signature_valid"] is True
    assert result["root_valid"] is True
    assert "algorithm_not_in_metadata" in result["errors"]
    assert result["metadata"]["description"] == "Demo authenticator"
    assert result["metadata"]["algorithm_supported"] is False
    assert result["root_checks"]["chain"] is True


def test_perform_attestation_checks_reports_an_mldsa_signature_that_does_not_verify(monkeypatch):
    challenge = b"pqc-fallback"
    rp_id = "example.com"
    auth_data = AuthData(rp_id=rp_id, flags=AuthData.FLAG.UP | AuthData.FLAG.UV | AuthData.FLAG.AT)
    client_data = ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"alg": -49, "sig": b"not-empty"},
        },
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    class _FailingAttestation:
        def verify(self, *_args, **_kwargs):
            raise InvalidSignature("bad signature")

    monkeypatch.setattr(Attestation, "for_type", lambda _fmt: _FailingAttestation)

    result = _perform_checks(
        response={"raw": "value"},
        state={"challenge": b64u(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is False
    assert result["root_valid"] is False
    assert any(error.startswith("attestation_invalid:") for error in result["errors"])
    assert "attestation_signature_invalid" in result["errors"]
