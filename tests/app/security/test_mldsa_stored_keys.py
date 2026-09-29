"""ML-DSA keys rebuilt from a stored credential are the raw keys a COSE key holds.

fido2 reads an ML-DSA COSE key's ``-1`` as the raw public key;
``webauthn.mldsa.with_raw_public_key`` turns one saved as SubjectPublicKeyInfo
into that, and leaves everything else as it is.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

from server.app.webauthn import mldsa as mldsa_keys


@pytest.mark.parametrize(
    "algorithm, private_key_class",
    [(-48, mldsa.MLDSA44PrivateKey), (-49, mldsa.MLDSA65PrivateKey), (-50, mldsa.MLDSA87PrivateKey)],
)
def test_an_mldsa_key_saved_as_subject_public_key_info_is_rebuilt_raw(algorithm, private_key_class):
    public_key = private_key_class.generate().public_key()
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = public_key.public_bytes_raw()

    assert mldsa_keys.with_raw_public_key({1: 7, 3: algorithm, -1: spki}) == {1: 7, 3: algorithm, -1: raw}
    stored_raw = {1: 7, 3: algorithm, -1: raw}
    assert mldsa_keys.with_raw_public_key(stored_raw) is stored_raw


def test_anything_but_an_mldsa_subject_public_key_info_is_left_as_it_is():
    ec_spki = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    unchanged = [
        {1: 7, 3: -48, -1: ec_spki},  # another algorithm's key
        {1: 7, 3: -48, -1: b"\x30\x03\x02\x01\x00"},  # DER, but not a key
        {1: 7, 3: -48, -1: "not bytes"},
        {1: 2, 3: -7, -1: 1, -2: b"x", -3: b"y"},
        {1: 7, 3: -48},
    ]
    for cose_key in unchanged:
        assert mldsa_keys.with_raw_public_key(cose_key) is cose_key
    assert mldsa_keys.with_raw_public_key([1, 2]) == [1, 2]
