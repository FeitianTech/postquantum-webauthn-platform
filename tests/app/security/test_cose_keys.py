"""The COSE keys the app adds to fido2's.

``webauthn.cose_keys`` defines RS384, RS512, PS384 and PS512, which fido2's
``CoseKey`` lookups find once the module is imported, and legacy credential
pickles that named them in ``fido2.cose`` read as those classes.
"""
from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fido2.cose import CoseKey

from server.app.storage import record_format
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


# pickle.dumps([{"credential_data": fido2.cose.RS384({...})}], protocol=4), made
# when fido2.cose defined RS384: a legacy .pkl names the class there.
_LEGACY_RS384_PICKLE = bytes.fromhex(
    "80049555000000000000005d947d948c0f63726564656e7469616c5f64617461948c0a6669646f322e636f7365948c05"
    "5253333834949394298194284b014b034b034afefeffff4affffffff43020102944afeffffff4303010001947573612e"
)


def test_a_legacy_pickle_naming_fido2_cose_rs384_reads_as_the_apps_class():
    records = record_format.restricted_pickle_loads(_LEGACY_RS384_PICKLE)

    key = records[0]["credential_data"]
    assert type(key) is cose_keys.RS384
    assert dict(key) == {1: 3, 3: -258, -1: b"\x01\x02", -2: b"\x01\x00\x01"}
