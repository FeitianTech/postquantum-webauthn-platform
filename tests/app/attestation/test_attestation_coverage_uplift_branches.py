from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

from server.app.webauthn.attestation import certificates as attestation_certificates


class _CredentialData:
    def __init__(self, public_key=None):
        self.credential_id = b"credential-id"
        self.public_key = public_key if public_key is not None else {3: -7}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _AuthData:
    def __init__(self, *, rp_id: str, flags: int, credential_data: _CredentialData | None = None):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = 1
        self.credential_data = credential_data or _CredentialData()

    def __bytes__(self):
        return b"auth-data"


class _ClientData:
    def __init__(self, *, challenge: bytes, origin: str):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = False
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration(attestation_object, client_data):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results={},
    )


def test_coerce_attestation_certificate_bytes_string_path_falls_back_to_base64url():
    raw = b"\xfb\xef\xbe"
    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard or "/" in standard
    assert "-" in urlsafe or "_" in urlsafe

    # Standard base64 first, then base64url -- and each reading is exact, so
    # the fallback recovers the same certificate rather than a shorter one.
    assert attestation_certificates._coerce_attestation_certificate_bytes(standard) == raw
    assert attestation_certificates._coerce_attestation_certificate_bytes(urlsafe) == raw

    assert attestation_certificates._coerce_attestation_certificate_bytes("not a certificate!") is None
