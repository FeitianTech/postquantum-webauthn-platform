"""Inputs shared by the decoder tests."""

import hashlib


def _build_attestation_object(*, rp_id: str = "example.com", counter: int = 1, credential_id: bytes = b"codec-cred"):
    from fido2.cose import CoseKey
    from fido2.webauthn import (
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
    )

    cose_key = CoseKey.parse(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )
    attested_credential = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(rp_id.encode("utf-8")).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        counter=counter,
        credential_data=attested_credential,
    )
    return AttestationObject.create("none", auth_data, {})


def _build_attestation_and_auth_data() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import (
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
    )

    credential_id = b"pipeline-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        2,
        credential_data,
    )
    attestation = AttestationObject.create("none", auth_data, {})
    return bytes(attestation), bytes(auth_data)
