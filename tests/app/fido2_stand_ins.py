"""Stand-ins for the fido2 objects a registration's checks read, built without a signature.

A test patches ``RegistrationResponse.from_dict`` to return ``registration(...)``, so
``checks.perform_attestation_checks`` reads these instead of parsing and verifying.
Each models what a client could send; none models what fido2 could never hand back.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

from fido2.webauthn import AuthenticatorData

AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")
ES256_KEY = {1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
UP_AT = int(AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT)
_A_CREDENTIAL = object()


class CredentialData:
    def __init__(self, *, credential_id: bytes = b"credential-id", public_key: Any = None, aaguid: bytes = AAGUID):
        self.credential_id = credential_id
        self.public_key = dict(ES256_KEY) if public_key is None else public_key
        self.aaguid = aaguid


class AuthData:
    FLAG = AuthenticatorData.FLAG

    def __init__(
        self, *, rp_id: str = "example.com", flags: int = UP_AT, counter: int = 1, credential_data: Any = _A_CREDENTIAL
    ):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = counter
        # None, as fido2 gives it for authData without attested credential data.
        self.credential_data = CredentialData() if credential_data is _A_CREDENTIAL else credential_data

    def __bytes__(self) -> bytes:
        return b"auth-data"


class ClientData:
    def __init__(
        self,
        *,
        challenge: bytes,
        origin: str = "https://example.com",
        type_value: str = "webauthn.create",
        cross_origin: bool = False,
    ):
        self.type = type_value
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = cross_origin
        self.hash = hashlib.sha256(b"client-data").digest()

    def __bytes__(self) -> bytes:
        return b"client-data-json"


def attestation_object(*, fmt: str = "none", att_stmt: Any = None, auth_data: Any = None) -> SimpleNamespace:
    return SimpleNamespace(fmt=fmt, att_stmt={} if att_stmt is None else att_stmt, auth_data=auth_data or AuthData())


def registration(attestation: Any, client_data: Any, extension_results: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        response=SimpleNamespace(attestation_object=attestation, client_data=client_data),
        client_extension_results={} if extension_results is None else extension_results,
    )
