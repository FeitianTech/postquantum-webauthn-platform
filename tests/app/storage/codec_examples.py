"""Inputs shared by the storage tests."""

from tests.app.security.ceremony_helpers import b64u
from tests.app.storage.credential_seed import sample_public_key_bytes


def _stored_credential_entry(credential_id: bytes) -> dict:
    return {
        "credentialId": b64u(credential_id),
        "publicKey": b64u(sample_public_key_bytes()),
        "aaguid": b64u(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "signCount": 3,
        "resident": True,
        "authenticatorAttachment": "platform",
        "algorithm": -7,
    }
