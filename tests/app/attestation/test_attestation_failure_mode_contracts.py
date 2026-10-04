
from fido2.attestation import (
    Attestation,
    AttestationResult,
    AttestationType,
    InvalidSignature,
)
from fido2.webauthn import Aaguid, RegistrationResponse

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import checks as attestation_checks
from server.app.webauthn.attestation import evaluation
from tests.app import fido2_stand_ins
from tests.app.entry_app import entry_app
from tests.app.fido2_stand_ins import (
    AuthData,
    ClientData,
)
from tests.app.security.ceremony_helpers import b64u


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
