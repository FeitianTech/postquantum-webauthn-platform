from datetime import datetime, timedelta, timezone

from fido2.webauthn import RegistrationResponse

from server.app.webauthn.attestation import checks as attestation_checks
from tests.app import fido2_stand_ins
from tests.app.fido2_stand_ins import (
    AuthData,
    ClientData,
)
from tests.app.security.ceremony_helpers import b64u


class _FakeSubject:
    def __init__(self, text: str):
        self._text = text

    def rfc4514_string(self) -> str:
        return self._text


class _FakeExtensionResult:
    def __init__(self, value):
        self.value = value


class _FakeExtensions:
    def __init__(self, extension_map, missing_exception):
        self._extension_map = extension_map
        self._missing_exception = missing_exception

    def get_extension_for_class(self, extension_cls):
        if extension_cls in self._extension_map:
            return _FakeExtensionResult(self._extension_map[extension_cls])
        raise self._missing_exception()


class _FakeCertificate:
    def __init__(self, *, subject: str, extension_map, missing_exception):
        now = datetime.now(timezone.utc)
        self.subject = _FakeSubject(subject)
        self.not_valid_before_utc = now - timedelta(days=1)
        self.not_valid_after_utc = now + timedelta(days=1)
        self.extensions = _FakeExtensions(extension_map, missing_exception)


def test_perform_attestation_checks_reports_core_validation_failures(monkeypatch):
    expected_challenge = b"expected-challenge"
    actual_challenge = b"different-challenge"

    auth_data = AuthData(rp_id="wrong-rp.example", flags=AuthData.FLAG.AT)
    client_data = ClientData(
        challenge=actual_challenge,
        origin="https://evil.example",
    )
    attestation_object = type(
        "_AttestationObject",
        (),
        {"fmt": "none", "auth_data": auth_data, "att_stmt": {}},
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    result = attestation_checks.perform_attestation_checks(
        response={"raw": "value"},
        state={"challenge": b64u(expected_challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -257}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["signature_valid"] is None
    assert result["rp_id_hash_valid"] is False
    assert result["authenticator_data"]["algorithm"] == -7
    assert result["authenticator_data"]["algorithm_allowed"] is False

    errors = set(result["errors"])
    assert "challenge_mismatch" in errors
    assert "origin_mismatch" in errors
    assert "rp_id_hash_mismatch" in errors
    assert "user_presence_missing" in errors
    assert "user_verification_required_not_satisfied" in errors
    assert "algorithm_not_allowed" in errors


def test_perform_attestation_checks_accepts_valid_none_attestation(monkeypatch):
    rp_id = "example.com"
    expected_challenge = b"valid-challenge"

    auth_data = AuthData(rp_id=rp_id, flags=AuthData.FLAG.UP | AuthData.FLAG.UV | AuthData.FLAG.AT)
    client_data = ClientData(
        challenge=expected_challenge,
        origin="https://example.com",
        cross_origin=False,
    )
    attestation_object = type(
        "_AttestationObject",
        (),
        {"fmt": "none", "auth_data": auth_data, "att_stmt": {}},
    )()

    registration = fido2_stand_ins.registration(attestation_object, client_data)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    result = attestation_checks.perform_attestation_checks(
        response={"raw": "value"},
        state={"challenge": b64u(expected_challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id=rp_id,
    )

    assert result["errors"] == []
    assert result["rp_id_hash_valid"] is True
    assert result["client_data"]["challenge_matches"] is True
    assert result["client_data"]["origin_valid"] is True
    assert result["authenticator_data"]["algorithm_allowed"] is True
    assert result["authenticator_data"]["user_present"] is True
    assert result["authenticator_data"]["user_verification_satisfied"] is True


def test_perform_attestation_checks_returns_registration_parse_error(monkeypatch):
    def _raise_parse_error(_value):
        raise ValueError("invalid payload")

    monkeypatch.setattr(RegistrationResponse, "from_dict", _raise_parse_error)

    result = attestation_checks.perform_attestation_checks(
        response={"broken": True},
        state=None,
        public_key_options=None,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["errors"]
    assert result["errors"][0].startswith("registration_parse_error")
