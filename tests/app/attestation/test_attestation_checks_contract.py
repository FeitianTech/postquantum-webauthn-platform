import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fido2.webauthn import RegistrationResponse


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _FakeCredentialData:
    def __init__(self, *, algorithm: int = -7):
        self.credential_id = b"cred-id"
        self.public_key = {1: 2, 3: algorithm, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _FakeAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, *, rp_id_hash: bytes, flags: int, counter: int = 1, algorithm: int = -7):
        self.rp_id_hash = rp_id_hash
        self.flags = flags
        self.counter = counter
        self.credential_data = _FakeCredentialData(algorithm=algorithm)

    def __bytes__(self):
        return self.rp_id_hash + bytes([self.flags]) + int(self.counter).to_bytes(4, "big")


class _FakeClientData:
    def __init__(self, *, challenge: bytes, origin: str, cross_origin: bool = False):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = cross_origin
        self.hash = hashlib.sha256(b"client-data").digest()


class _FakeRegistrationResponse:
    def __init__(self, client_data, attestation_object):
        self.response = type(
            "_Response",
            (),
            {
                "client_data": client_data,
                "attestation_object": attestation_object,
            },
        )()


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


def test_perform_attestation_checks_reports_core_validation_failures(monkeypatch, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    expected_challenge = b"expected-challenge"
    actual_challenge = b"different-challenge"

    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(b"wrong-rp.example").digest(),
        flags=_FakeAuthData.FLAG.AT,
        algorithm=-7,
    )
    client_data = _FakeClientData(
        challenge=actual_challenge,
        origin="https://evil.example",
    )
    attestation_object = type(
        "_AttestationObject",
        (),
        {"fmt": "none", "auth_data": auth_data, "att_stmt": {}},
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    result = attestation_module.perform_attestation_checks(
        response={"raw": "value"},
        state={"challenge": _b64url(expected_challenge), "user_verification": "required"},
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


def test_perform_attestation_checks_accepts_valid_none_attestation(monkeypatch, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    rp_id = "example.com"
    expected_challenge = b"valid-challenge"

    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
        algorithm=-7,
    )
    client_data = _FakeClientData(
        challenge=expected_challenge,
        origin="https://example.com",
        cross_origin=False,
    )
    attestation_object = type(
        "_AttestationObject",
        (),
        {"fmt": "none", "auth_data": auth_data, "att_stmt": {}},
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(RegistrationResponse, "from_dict", lambda _value: registration)

    result = attestation_module.perform_attestation_checks(
        response={"raw": "value"},
        state={"challenge": _b64url(expected_challenge), "user_verification": "required"},
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


def test_perform_attestation_checks_returns_registration_parse_error(monkeypatch, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    def _raise_parse_error(_value):
        raise ValueError("invalid payload")

    monkeypatch.setattr(RegistrationResponse, "from_dict", _raise_parse_error)

    result = attestation_module.perform_attestation_checks(
        response={"broken": True},
        state=None,
        public_key_options=None,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["errors"]
    assert result["errors"][0].startswith("registration_parse_error")


@pytest.mark.parametrize(
    "checks,expected",
    [
        ({"trusted_ca": True, "chain": True, "fido_mds": None}, True),
        ({"trusted_ca": True, "chain": False, "fido_mds": False}, False),
        ({"trusted_ca": True, "chain": None, "fido_mds": None}, None),
        ({"trusted_ca": False, "chain": True, "fido_mds": False}, True),
        ({"trusted_ca": False, "chain": False, "fido_mds": False}, False),
        ({"trusted_ca": None, "chain": True, "fido_mds": True}, None),
    ],
)
def test_resolve_root_validity_matrix(checks, expected, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module._resolve_root_validity(checks) is expected


@pytest.mark.parametrize(
    "checks,expected",
    [
        ({"trusted_ca": True, "chain": True, "fido_mds": False}, True),
        ({"trusted_ca": True, "chain": False, "fido_mds": True}, True),
        ({"trusted_ca": False, "chain": None, "fido_mds": False}, False),
        ({"trusted_ca": None, "chain": True, "fido_mds": False}, None),
    ],
)
def test_resolve_root_validity_additional_matrix_cases(checks, expected, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module._resolve_root_validity(checks) is expected


def test_resolve_root_validity_returns_none_when_all_checks_unknown(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert (
        attestation_module._resolve_root_validity(
            {
                "trusted_ca": None,
                "chain": None,
                "fido_mds": None,
            }
        )
        is None
    )
