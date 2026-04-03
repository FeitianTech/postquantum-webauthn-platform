import base64
import hashlib

import pytest


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


def _perform_checks(attestation_module, response, state, public_key_options, rp_id="example.com"):
    return attestation_module.perform_attestation_checks(
        response=response,
        state=state,
        public_key_options=public_key_options,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id=rp_id,
    )


def test_perform_attestation_checks_unsupported_format_sets_signature_and_root_failure(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    challenge = b"challenge"
    rp_id = "example.com"
    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
    )
    client_data = _FakeClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "vendor-unknown",
            "auth_data": auth_data,
            "att_stmt": {},
        },
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(attestation_module.RegistrationResponse, "from_dict", lambda _value: registration)

    result = _perform_checks(
        attestation_module,
        response={"raw": "value"},
        state={"challenge": _b64url(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is False
    assert result["root_valid"] is False
    assert "attestation_signature_invalid" in result["errors"]
    assert any(error.startswith("unsupported_attestation:") for error in result["errors"])


def test_perform_attestation_checks_warns_when_metadata_verifier_unavailable(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    challenge = b"metadata-unavailable"
    rp_id = "example.com"
    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
    )
    client_data = _FakeClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"sig": b"signature"},
        },
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(attestation_module.RegistrationResponse, "from_dict", lambda _value: registration)

    class _PassingAttestation:
        def verify(self, *_args, **_kwargs):
            return attestation_module.AttestationResult(attestation_module.AttestationType.BASIC, [])

    monkeypatch.setattr(attestation_module.Attestation, "for_type", lambda _fmt: _PassingAttestation)
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: None)

    result = _perform_checks(
        attestation_module,
        response={"raw": "value"},
        state={"challenge": _b64url(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is True
    assert result["root_valid"] is None
    assert "metadata_not_available" in result["warnings"]
    assert "trust_path_missing" in result["errors"]


def test_perform_attestation_checks_captures_verifier_evaluation_exception(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    challenge = b"verifier-exception"
    rp_id = "example.com"
    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
    )
    client_data = _FakeClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"sig": b"signature"},
        },
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(attestation_module.RegistrationResponse, "from_dict", lambda _value: registration)

    class _PassingAttestation:
        def verify(self, *_args, **_kwargs):
            return attestation_module.AttestationResult(attestation_module.AttestationType.BASIC, [])

    class _FailingVerifier:
        def evaluate_attestation(self, *_args, **_kwargs):
            raise RuntimeError("verifier exploded")

    monkeypatch.setattr(attestation_module.Attestation, "for_type", lambda _fmt: _PassingAttestation)
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: _FailingVerifier())

    result = _perform_checks(
        attestation_module,
        response={"raw": "value"},
        state={"challenge": _b64url(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is True
    assert any(error.startswith("untrusted_attestation: verifier exploded") for error in result["errors"])
    assert "metadata_entry_missing" in result["errors"]
    assert result["root_checks"]["trusted_ca"] is False


def test_perform_attestation_checks_flags_algorithm_not_in_metadata_when_root_is_valid(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    challenge = b"metadata-algorithm"
    rp_id = "example.com"
    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
        algorithm=-7,
    )
    client_data = _FakeClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"sig": b"signature"},
        },
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(attestation_module.RegistrationResponse, "from_dict", lambda _value: registration)

    class _PassingAttestation:
        def verify(self, *_args, **_kwargs):
            return attestation_module.AttestationResult(attestation_module.AttestationType.BASIC, [])

    trust_path = attestation_module.TrustPathEvaluation(
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
            "aaguid": attestation_module.Aaguid.fromhex("00112233445566778899aabbccddeeff"),
        },
    )()

    evaluation = type(
        "_Evaluation",
        (),
        {
            "trust_path": trust_path,
            "metadata_entry": metadata_entry,
            "metadata_lookup_source": "aaguid",
        },
    )()

    class _Verifier:
        def evaluate_attestation(self, *_args, **_kwargs):
            return evaluation

    monkeypatch.setattr(attestation_module.Attestation, "for_type", lambda _fmt: _PassingAttestation)
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: _Verifier())

    result = _perform_checks(
        attestation_module,
        response={"raw": "value"},
        state={"challenge": _b64url(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is True
    assert result["root_valid"] is True
    assert "algorithm_not_in_metadata" in result["errors"]
    assert result["metadata"]["description"] == "Demo authenticator"
    assert result["metadata"]["algorithm_supported"] is False
    assert result["root_checks"]["chain"] is True


def test_perform_attestation_checks_reports_pqc_algorithm_mismatch_during_fallback(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    challenge = b"pqc-fallback"
    rp_id = "example.com"
    auth_data = _FakeAuthData(
        rp_id_hash=hashlib.sha256(rp_id.encode("utf-8")).digest(),
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.UV | _FakeAuthData.FLAG.AT,
        algorithm=-7,
    )
    client_data = _FakeClientData(challenge=challenge, origin="https://example.com")
    attestation_object = type(
        "_AttestationObject",
        (),
        {
            "fmt": "packed",
            "auth_data": auth_data,
            "att_stmt": {"alg": -49, "sig": b"not-empty"},
        },
    )()

    registration = _FakeRegistrationResponse(client_data, attestation_object)
    monkeypatch.setattr(attestation_module.RegistrationResponse, "from_dict", lambda _value: registration)

    class _FailingAttestation:
        def verify(self, *_args, **_kwargs):
            raise attestation_module.InvalidSignature("bad signature")

    monkeypatch.setattr(attestation_module.Attestation, "for_type", lambda _fmt: _FailingAttestation)

    result = _perform_checks(
        attestation_module,
        response={"raw": "value"},
        state={"challenge": _b64url(challenge), "user_verification": "required"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        rp_id=rp_id,
    )

    assert result["signature_valid"] is False
    assert result["root_valid"] is False
    assert any(error.startswith("attestation_invalid:") for error in result["errors"])
    assert "pqc_attestation_algorithm_mismatch" in result["errors"]
    assert "attestation_signature_invalid" in result["errors"]