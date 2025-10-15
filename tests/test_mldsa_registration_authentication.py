"""Tests for ML-DSA registration and authentication flows."""

import hashlib
from typing import Type

import pytest

from fido2 import cose
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
)

ML_DSA_VARIANTS = [
    ("ML-DSA-44", cose.MLDSA44, cose.MLDSA44.ALGORITHM, 1312),
    ("ML-DSA-65", cose.MLDSA65, cose.MLDSA65.ALGORITHM, 1952),
    ("ML-DSA-87", cose.MLDSA87, cose.MLDSA87.ALGORITHM, 2592),
]


@pytest.mark.parametrize("label, cose_cls, alg_id, key_length", ML_DSA_VARIANTS)
def test_mldsa_registration_and_authentication(label: str, cose_cls: Type[cose.CoseKey], alg_id: int, key_length: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end style test covering registration and authentication for ML-DSA."""

    rp = PublicKeyCredentialRpEntity(name="Example RP", id="example.com")
    server = Fido2Server(rp, attestation=AttestationConveyancePreference.NONE)
    user = {"id": hashlib.sha256(label.encode()).digest(), "name": f"{label} User"}

    creation_options, state = server.register_begin(user)

    client_data_create = CollectedClientData.create(
        CollectedClientData.TYPE.CREATE,
        creation_options.public_key.challenge,
        "https://example.com",
    )

    credential_id = hashlib.sha256(f"{label}-credential".encode()).digest()
    public_key_bytes = bytes((idx % 256 for idx in range(key_length)))
    public_key = cose_cls({1: 7, 3: alg_id, -1: public_key_bytes})

    attested_credential = AttestedCredentialData.create(
        bytes(16),
        credential_id,
        public_key,
    )
    auth_data_create = AuthenticatorData.create(
        server.rp.id_hash,
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        counter=1,
        credential_data=attested_credential,
    )

    attestation_signature = hashlib.sha256(f"{label}-attestation".encode()).digest()
    attestation_object = AttestationObject.create(
        "packed",
        auth_data_create,
        {"alg": alg_id, "sig": attestation_signature},
    )

    assert attestation_object.att_stmt["alg"] == alg_id
    assert attestation_object.att_stmt["sig"] == attestation_signature

    stored_auth_data = server.register_complete(state, client_data_create, attestation_object)

    assert isinstance(stored_auth_data.credential_data.public_key, cose_cls)
    assert stored_auth_data.credential_data.credential_id == credential_id

    request_options, auth_state = server.authenticate_begin([stored_auth_data.credential_data])

    client_data_get = CollectedClientData.create(
        CollectedClientData.TYPE.GET,
        request_options.public_key.challenge,
        "https://example.com",
    )

    auth_data_get = AuthenticatorData.create(
        server.rp.id_hash,
        AuthenticatorData.FLAG.UP,
        counter=2,
    )

    assertion_message = auth_data_get + client_data_get.hash
    signature_prefix = f"{label}-assertion".encode()
    assertion_signature = hashlib.sha256(signature_prefix + assertion_message).digest()

    def _stub_verify(self, message: bytes, signature: bytes, *, expected_message=assertion_message, expected_signature=assertion_signature) -> None:
        assert message == expected_message
        assert signature == expected_signature

    monkeypatch.setattr(cose_cls, "verify", _stub_verify)

    authenticated_credential = server.authenticate_complete(
        auth_state,
        [stored_auth_data.credential_data],
        credential_id,
        client_data_get,
        auth_data_get,
        assertion_signature,
    )

    assert authenticated_credential.credential_id == credential_id
    assert authenticated_credential.public_key[3] == alg_id
