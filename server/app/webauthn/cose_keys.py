"""The COSE algorithms the app verifies beyond fido2's own: RS384, RS512, PS384 and PS512.

fido2 finds a key class by walking ``CoseKey``'s subclasses, so defining these is
all it takes for ``CoseKey.for_alg`` and ``CoseKey.parse`` to use them once this
module is imported; ``server.app.webauthn`` imports it. Each is fido2's RS256 or
PS256 with another hash (RFC 8812).
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from fido2.cose import PS256, RS256

__all__ = ["BY_NAME", "PS384", "PS512", "RS384", "RS512"]


class RS384(RS256):
    ALGORITHM = -258
    _HASH_ALG = hashes.SHA384()


class RS512(RS256):
    ALGORITHM = -259
    _HASH_ALG = hashes.SHA512()


class PS384(PS256):
    ALGORITHM = -38
    _HASH_ALG = hashes.SHA384()


class PS512(PS256):
    ALGORITHM = -39
    _HASH_ALG = hashes.SHA512()


# By class name: how a legacy credential pickle names them (as ``fido2.cose.<name>``).
BY_NAME: dict[str, type] = {cls.__name__: cls for cls in (RS384, RS512, PS384, PS512)}
