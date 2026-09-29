"""The COSE keys the app adds to fido2's.

``webauthn.cose_keys`` defines RS384, RS512, PS384 and PS512, which fido2's
``CoseKey`` lookups find once the module is imported.
"""
from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fido2.cose import CoseKey

from server.app.webauthn import cose_keys

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_MESSAGE = b"authenticator data and client data hash"


def _pkcs1(hash_algorithm):
    return _RSA_KEY.sign(_MESSAGE, padding.PKCS1v15(), hash_algorithm)


def _pss(hash_algorithm):
    return _RSA_KEY.sign(_MESSAGE, padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH), hash_algorithm)


@pytest.mark.parametrize(
    "cls, algorithm, sign, hash_algorithm",
    [
        (cose_keys.RS384, -258, _pkcs1, hashes.SHA384()),
        (cose_keys.RS512, -259, _pkcs1, hashes.SHA512()),
        (cose_keys.PS384, -38, _pss, hashes.SHA384()),
        (cose_keys.PS512, -39, _pss, hashes.SHA512()),
    ],
)
def test_each_key_verifies_its_own_signatures_and_no_others(cls, algorithm, sign, hash_algorithm):
    key = cls.from_cryptography_key(_RSA_KEY.public_key())

    assert key[3] == algorithm
    assert CoseKey.for_alg(algorithm).__name__ == cls.__name__
    assert type(CoseKey.parse(dict(key))).__name__ == cls.__name__
    key.verify(_MESSAGE, sign(hash_algorithm))
    with pytest.raises(InvalidSignature):
        key.verify(_MESSAGE, sign(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        key.verify(b"another message", sign(hash_algorithm))
