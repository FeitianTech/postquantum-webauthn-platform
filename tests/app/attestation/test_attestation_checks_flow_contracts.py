import hashlib
from types import SimpleNamespace

from fido2.attestation import Attestation
from fido2.webauthn import AuthenticatorData, CollectedClientData, RegistrationResponse

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import checks as attestation_checks


class _FakeCredentialData:
    def __init__(self, alg: int):
        self.credential_id = b"credential-id"
        self.public_key = {1: 2, 3: alg, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.aaguid = b"\x00" * 16


class _FakeAuthData:
    def __init__(self, *, rp_id: str, flags: int, counter: int, alg: int):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = counter
        self.credential_data = _FakeCredentialData(alg)

    def __bytes__(self):
        return b"auth-data"


class _FakeClientData:
    def __init__(self, *, challenge: bytes, type_value: str, origin: str, cross_origin: bool):
        self.challenge = challenge
        self.type = type_value
        self.origin = origin
        self.cross_origin = cross_origin
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration_for(attestation_object, client_data, *, extensions=None):
    return SimpleNamespace(
        response=SimpleNamespace(attestation_object=attestation_object, client_data=client_data),
        client_extension_results=extensions or {},
    )


def test_perform_attestation_checks_reports_client_authenticator_mismatches(monkeypatch, attestation_module):
    auth_data = _FakeAuthData(rp_id="wrong.example", flags=0, counter=0, alg=-7)
    attestation_object = SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data)
    client_data = _FakeClientData(
        challenge=b"actual-challenge",
        type_value="webauthn.get",
        origin="https://origin.example",
        cross_origin=True,
    )

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: _registration_for(attestation_object, client_data),
    )

    result = attestation_checks.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": b"expected-challenge", "user_verification": "required"},
        public_key_options={
            "challenge": b"expected-challenge",
            "pubKeyCredParams": [{"alg": -7}],
            "authenticatorSelection": {"userVerification": "required"},
        },
        auth_data=auth_data,
        expected_origin="https://expected.example",
        rp_id="expected.example",
    )

    assert result["signature_valid"] is None
    assert result["rp_id_hash_valid"] is False
    assert "client_data_type_invalid" in result["errors"]
    assert "challenge_mismatch" in result["errors"]
    assert "origin_mismatch" in result["errors"]
    assert "cross_origin_not_allowed" in result["errors"]
    assert "user_presence_missing" in result["errors"]
    assert "user_verification_required_not_satisfied" in result["errors"]
    assert "attested_credential_data_missing" in result["errors"]


def test_perform_attestation_checks_classical_success_path_populates_metadata(monkeypatch, classical, metadata_module, attestation_module):
    flags = int(AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT)
    auth_data = _FakeAuthData(rp_id="example.com", flags=flags, counter=7, alg=-7)
    attestation_object = SimpleNamespace(fmt="packed", att_stmt={"alg": -7}, auth_data=auth_data)
    client_data = _FakeClientData(
        challenge=b"expected",
        type_value=CollectedClientData.TYPE.CREATE.value,
        origin="https://example.com",
        cross_origin=False,
    )

    class _FakeAttestation:
        def verify(self, _att_stmt, _auth_data, _client_data_hash):
            return SimpleNamespace(trust_path=[b"cert"])

    metadata_statement = SimpleNamespace(
        description="Demo metadata entry",
        authenticator_get_info={"algorithms": [-7]},
        attestation_root_certificates=["cert"],
    )
    metadata_entry = SimpleNamespace(metadata_statement=metadata_statement, aaguid=b"\x00" * 16)

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: _registration_for(attestation_object, client_data),
    )
    monkeypatch.setattr(Attestation, "for_type", lambda _fmt: (lambda: _FakeAttestation()))
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: object())
    monkeypatch.setattr(
        classical,
        "_evaluate_classical_attestation_root",
        lambda *_args, **_kwargs: {
            "root_valid": True,
            "metadata_entry": metadata_entry,
            "metadata_lookup_source": "aaguid",
            "checks": {"trusted_ca": True, "chain": True, "fido_mds": True},
            "errors": [],
            "warnings": [],
        },
    )

    result = attestation_checks.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": b"expected", "user_verification": "preferred"},
        public_key_options={"challenge": b"expected", "pubKeyCredParams": [{"alg": -7}]},
        auth_data=auth_data,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["signature_valid"] is True
    assert result["root_valid"] is True
    assert result["metadata"]["available"] is True
    assert result["metadata"]["description"] == "Demo metadata entry"
    assert result["metadata"]["algorithm_supported"] is True
    assert result["metadata"]["root_certificates_present"] is True
    assert result["metadata"]["source"] == "aaguid"
