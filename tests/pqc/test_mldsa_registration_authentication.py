"""Real ML-DSA registration and authentication tests.

Every signature in this module is produced by ``cryptography``'s ML-DSA
implementation and checked by the production code paths.  No verification
function is monkeypatched, stubbed or replaced anywhere in this file: if
``CoseKey.verify``, ``PackedAttestation.verify`` or ``verify_x509_chain``
stopped checking anything, these tests fail.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.exceptions import InvalidSignature

from fido2.attestation import Attestation, AttestationVerifier, UntrustedAttestation
from fido2.attestation.base import InvalidData
from fido2.attestation.base import InvalidSignature as AttestationInvalidSignature
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
)
from tests.pqc import mldsa_helpers as mldsa

ORIGIN = "https://example.com"
RP_ID = "example.com"
AAGUID = bytes(range(16))


pytestmark = pytest.mark.parametrize("parameter_set", mldsa.PARAMETER_SETS)


def _run_real_attestation(attestation_object, client_data_hash) -> None:
    """Run the production packed-attestation verifier, unmodified."""

    Attestation.for_type(attestation_object.fmt)().verify(
        attestation_object.att_stmt,
        attestation_object.auth_data,
        client_data_hash,
    )


class _ChainVerifier(AttestationVerifier):
    """Real AttestationVerifier that trusts one ML-DSA root certificate."""

    def __init__(self, ca: bytes):
        super().__init__()
        self._ca = ca

    def ca_lookup(self, attestation_result, auth_data) -> bytes | None:
        return self._ca


def _register(
    parameter_set: str,
    *,
    server: Fido2Server,
    credential_label: str = "credential",
    statement_signer: str | None = None,
    x5c: list[bytes] | None = None,
    tamper_signature: bool = False,
):
    """Drive a complete registration ceremony and return the stored auth data."""

    alg = mldsa.COSE_ALGORITHMS[parameter_set]
    user = {
        "id": hashlib.sha256(parameter_set.encode()).digest(),
        "name": f"{parameter_set} User",
    }
    options, state = server.register_begin(user)
    client_data = CollectedClientData.create(
        CollectedClientData.TYPE.CREATE,
        options.public_key.challenge,
        ORIGIN,
    )

    credential_id = hashlib.sha256(f"{parameter_set}-credential".encode()).digest()
    credential_data = AttestedCredentialData.create(
        AAGUID,
        credential_id,
        mldsa.cose_key(parameter_set, credential_label),
    )
    auth_data = AuthenticatorData.create(
        server.rp.id_hash,
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        counter=1,
        credential_data=credential_data,
    )

    # The packed attestation signature is over authenticatorData ||
    # SHA-256(clientDataJSON), signed with the attestation key.
    signed_message = bytes(auth_data) + client_data.hash
    signature = mldsa.sign(
        parameter_set, signed_message, statement_signer or credential_label
    )
    if tamper_signature:
        signature = mldsa.flip_bit(signature, index=len(signature) // 2)

    statement = {"alg": alg, "sig": signature}
    if x5c is not None:
        statement["x5c"] = x5c
    attestation_object = AttestationObject.create("packed", auth_data, statement)

    return server.register_complete(state, client_data, attestation_object)


def _authenticate(
    parameter_set: str,
    *,
    server: Fido2Server,
    credential_data,
    credential_label: str = "credential",
    signing_label: str | None = None,
    tamper_signature: bool = False,
    counter: int = 2,
):
    options, state = server.authenticate_begin([credential_data])
    client_data = CollectedClientData.create(
        CollectedClientData.TYPE.GET,
        options.public_key.challenge,
        ORIGIN,
    )
    auth_data = AuthenticatorData.create(
        server.rp.id_hash, AuthenticatorData.FLAG.UP, counter=counter
    )
    message = bytes(auth_data) + client_data.hash
    signature = mldsa.sign(parameter_set, message, signing_label or credential_label)
    if tamper_signature:
        signature = mldsa.flip_bit(signature, index=len(signature) // 3)

    return server.authenticate_complete(
        state,
        [credential_data],
        credential_data.credential_id,
        client_data,
        auth_data,
        signature,
    )


def test_cose_key_verifies_a_real_signature(parameter_set):
    """A real ML-DSA signature over authData || SHA-256(clientDataJSON)."""

    key = mldsa.cose_key(parameter_set)
    assert isinstance(key, mldsa.COSE_KEY_CLASSES[parameter_set])
    assert len(key[-1]) == mldsa.PUBLIC_KEY_LENGTHS[parameter_set]

    client_data_json = b'{"type":"webauthn.get","challenge":"Zm9v","origin":"' + ORIGIN.encode() + b'"}'
    authenticator_data = bytes([0xAA] * 37)
    message = authenticator_data + hashlib.sha256(client_data_json).digest()

    signature = mldsa.sign(parameter_set, message)
    assert len(signature) == mldsa.SIGNATURE_LENGTHS[parameter_set]

    key.verify(message, signature)


def test_cose_key_rejects_a_flipped_signature_bit(parameter_set):
    key = mldsa.cose_key(parameter_set)
    message = b"authenticator-data" + hashlib.sha256(b"client-data").digest()
    signature = mldsa.sign(parameter_set, message)

    for index in (0, len(signature) // 2, len(signature) - 1):
        with pytest.raises(InvalidSignature):
            key.verify(message, mldsa.flip_bit(signature, index=index))
        for bit in range(8):
            with pytest.raises(InvalidSignature):
                key.verify(message, mldsa.flip_bit(signature, index=index, bit=bit))


def test_cose_key_rejects_a_wrong_message(parameter_set):
    key = mldsa.cose_key(parameter_set)
    message = b"authenticator-data" + hashlib.sha256(b"client-data").digest()
    signature = mldsa.sign(parameter_set, message)

    for other in (
        message + b"\x00",
        message[:-1],
        b"authenticator-data" + hashlib.sha256(b"other-client-data").digest(),
        b"",
    ):
        with pytest.raises(InvalidSignature):
            key.verify(other, signature)


def test_cose_key_rejects_a_public_key_from_another_keypair(parameter_set):
    message = b"authenticator-data" + hashlib.sha256(b"client-data").digest()
    signature = mldsa.sign(parameter_set, message, "default")

    impostor = mldsa.cose_key(parameter_set, "other-keypair")
    assert impostor[-1] != mldsa.public_key_bytes(parameter_set, "default")
    with pytest.raises(InvalidSignature):
        impostor.verify(message, signature)

    # ... and the real key rejects the other keypair's signature.
    mldsa.cose_key(parameter_set).verify(message, signature)
    with pytest.raises(InvalidSignature):
        mldsa.cose_key(parameter_set).verify(
            message, mldsa.sign(parameter_set, message, "other-keypair")
        )


def test_cose_key_rejects_a_truncated_public_key(parameter_set):
    cls = mldsa.COSE_KEY_CLASSES[parameter_set]
    alg = mldsa.COSE_ALGORITHMS[parameter_set]
    raw = mldsa.public_key_bytes(parameter_set)
    message = b"authenticator-data" + hashlib.sha256(b"client-data").digest()
    signature = mldsa.sign(parameter_set, message)

    for broken in (raw[:-1], raw[:100], b"", raw + b"\x00"):
        key = cls({1: 7, 3: alg, -1: broken})
        with pytest.raises(ValueError, match="public key must be"):
            key.verify(message, signature)

    # A wrong key type is refused before any verification happens.
    with pytest.raises(ValueError, match="Unsupported"):
        cls({1: 2, 3: alg, -1: raw}).verify(message, signature)


def test_registration_and_authentication_round_trip(parameter_set):
    """A full ceremony with real signatures and no patched verification."""

    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_run_real_attestation,
    )

    auth_data = _register(parameter_set, server=server)
    credential_data = auth_data.credential_data
    assert isinstance(
        credential_data.public_key, mldsa.COSE_KEY_CLASSES[parameter_set]
    )
    assert credential_data.public_key[3] == mldsa.COSE_ALGORITHMS[parameter_set]
    assert credential_data.public_key[-1] == mldsa.public_key_bytes(
        parameter_set, "credential"
    )

    authenticated = _authenticate(
        parameter_set, server=server, credential_data=credential_data
    )
    assert authenticated.credential_id == credential_data.credential_id
    assert authenticated.public_key[3] == mldsa.COSE_ALGORITHMS[parameter_set]


def test_registration_rejects_a_forged_self_attestation(parameter_set):
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_run_real_attestation,
    )

    with pytest.raises(AttestationInvalidSignature):
        _register(parameter_set, server=server, tamper_signature=True)

    # A statement signed by a different keypair is a forgery too.
    with pytest.raises(AttestationInvalidSignature):
        _register(parameter_set, server=server, statement_signer="other-keypair")


def test_authentication_rejects_a_forged_assertion(parameter_set):
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_run_real_attestation,
    )
    credential_data = _register(parameter_set, server=server).credential_data

    with pytest.raises(ValueError, match="Invalid signature"):
        _authenticate(
            parameter_set,
            server=server,
            credential_data=credential_data,
            tamper_signature=True,
        )

    with pytest.raises(ValueError, match="Invalid signature"):
        _authenticate(
            parameter_set,
            server=server,
            credential_data=credential_data,
            signing_label="other-keypair",
        )


def test_packed_attestation_with_an_mldsa_certificate_chain(parameter_set):
    """x5c leaf is a real ML-DSA-signed certificate, verified up to its CA."""

    ca_der = mldsa.certificate(parameter_set, label="ca", ca=True)
    leaf_der = mldsa.certificate(
        parameter_set,
        label="attestation-leaf",
        issuer_label="ca",
        aaguid=AAGUID,
    )
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_ChainVerifier(ca_der),
    )

    auth_data = _register(
        parameter_set,
        server=server,
        statement_signer="attestation-leaf",
        x5c=[leaf_der],
    )
    assert auth_data.credential_data.public_key[3] == mldsa.COSE_ALGORITHMS[parameter_set]

    # The credential still authenticates with its own (different) key.
    _authenticate(
        parameter_set, server=server, credential_data=auth_data.credential_data
    )


def test_packed_attestation_rejects_a_forged_certificate_signature(parameter_set):
    leaf_der = mldsa.certificate(
        parameter_set,
        label="attestation-leaf",
        issuer_label="ca",
        aaguid=AAGUID,
    )
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_run_real_attestation,
    )

    # Attestation statement signed by a key that is not the certificate's.
    with pytest.raises(AttestationInvalidSignature):
        _register(
            parameter_set,
            server=server,
            statement_signer="credential",
            x5c=[leaf_der],
        )

    # A single flipped bit in an otherwise valid statement is a forgery too.
    with pytest.raises(AttestationInvalidSignature):
        _register(
            parameter_set,
            server=server,
            statement_signer="attestation-leaf",
            x5c=[leaf_der],
            tamper_signature=True,
        )


def test_packed_attestation_rejects_an_untrusted_certificate_chain(parameter_set):
    ca_der = mldsa.certificate(parameter_set, label="ca", ca=True)
    chain_server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_ChainVerifier(ca_der),
    )

    # A well-formed leaf issued by a CA the relying party does not trust:
    # the statement signature is valid, the trust path is not.
    untrusted_leaf = mldsa.certificate(
        parameter_set,
        label="rogue-leaf",
        issuer_label="rogue-ca",
        aaguid=AAGUID,
    )
    with pytest.raises(UntrustedAttestation):
        _register(
            parameter_set,
            server=chain_server,
            statement_signer="rogue-leaf",
            x5c=[untrusted_leaf],
        )


def test_packed_attestation_requires_certificate_fields(parameter_set):
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Example RP", id=RP_ID),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=_run_real_attestation,
    )

    # AAGUID in the certificate must match the authenticator data.
    mismatched = mldsa.certificate(
        parameter_set,
        label="attestation-leaf",
        issuer_label="ca",
        aaguid=bytes(16),
    )
    with pytest.raises(InvalidData, match="AAGUID"):
        _register(
            parameter_set,
            server=server,
            statement_signer="attestation-leaf",
            x5c=[mismatched],
        )

    # A CA=true leaf is not a valid attestation certificate.
    ca_leaf = mldsa.certificate(
        parameter_set,
        label="attestation-leaf",
        issuer_label="ca",
        aaguid=AAGUID,
        ca=True,
    )
    with pytest.raises(InvalidData, match="CA=false"):
        _register(
            parameter_set,
            server=server,
            statement_signer="attestation-leaf",
            x5c=[ca_leaf],
        )

    # Basic Constraints are mandatory for packed attestation certificates.
    no_basic_constraints = mldsa.certificate(
        parameter_set,
        label="attestation-leaf",
        issuer_label="ca",
        aaguid=AAGUID,
        basic_constraints=False,
    )
    with pytest.raises(InvalidData, match="Basic Constraints"):
        _register(
            parameter_set,
            server=server,
            statement_signer="attestation-leaf",
            x5c=[no_basic_constraints],
        )
