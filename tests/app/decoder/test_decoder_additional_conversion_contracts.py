from __future__ import annotations

import hashlib

from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import authenticator_data as decode_authenticator_data


def _build_auth_data_bytes() -> bytes:
    credential_id = b"decoder-extra-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        9,
        credential_data,
    )
    return bytes(auth_data)


def _build_attestation_bytes() -> bytes:
    auth_data = _build_auth_data_bytes()
    attestation = AttestationObject.create("none", AuthenticatorData(auth_data), {})
    return bytes(attestation)


def test_describe_authenticator_data_bytes_includes_flags_and_attested_credential_details():
    auth_bytes = _build_auth_data_bytes()
    details = decode_authenticator_data._describe_authenticator_data_bytes(auth_bytes)

    assert details["rpIdHash"]["hex"] == hashlib.sha256(b"example.com").hexdigest()
    assert details["flags"]["userPresent"] is True
    assert details["flags"]["attestedCredentialDataIncluded"] is True
    assert details["signCount"] == 9
    assert details["attestedCredentialData"]["credentialId"]["hex"]
