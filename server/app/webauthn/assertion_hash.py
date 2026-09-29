"""An assertion checked over clientDataJSON hashed with another algorithm than SHA-256.

WebAuthn signs ``authenticatorData || SHA-256(clientDataJSON)``. The Advanced
tab's hash choice lets a tester verify an authenticator that hashed the client
data otherwise. fido2's ``Fido2Server.authenticate_complete`` takes the hash from
``CollectedClientData.hash``, so the response it is given carries client data
whose ``hash`` uses the chosen algorithm; fido2 still makes every other check.
SHA-256 leaves the response exactly as it came.
"""
from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AuthenticationResponse, CollectedClientData

__all__ = ["HASH_ALGORITHMS", "hash_with_algorithm", "response_hashed_with"]

HASH_ALGORITHMS = {
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA-384": hashlib.sha384,
    "SHA-1": hashlib.sha1,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
}


def hash_with_algorithm(data: bytes, algorithm: str) -> bytes:
    """``data`` hashed with ``algorithm``, one of ``HASH_ALGORITHMS``."""

    hash_function = HASH_ALGORITHMS.get(algorithm)
    if hash_function is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hash_function(data).digest()


class _ClientDataHashedWith(CollectedClientData):
    """clientDataJSON whose ``hash`` is taken with ``algorithm``, when fido2 asks for it."""

    def __new__(cls, data: bytes, algorithm: str):
        return super().__new__(cls, data)

    def __init__(self, data: bytes, algorithm: str):
        super().__init__(data)
        object.__setattr__(self, "_algorithm", algorithm)

    @property
    def hash(self) -> bytes:
        # Only once a credential matched: an unknown algorithm is reported after
        # the origin, challenge, RP and flag checks, as fido2 orders them.
        return hash_with_algorithm(self, self._algorithm)


def response_hashed_with(response: AuthenticationResponse | Mapping[str, Any], algorithm: str) -> Any:
    """``response`` for ``Fido2Server.authenticate_complete``, its client data hashed with ``algorithm``."""

    if algorithm == "SHA-256":
        return response
    authentication = AuthenticationResponse.from_dict(response)
    assertion = authentication.response
    client_data = _ClientDataHashedWith(bytes(assertion.client_data), algorithm)
    return dataclasses.replace(authentication, response=dataclasses.replace(assertion, client_data=client_data))
