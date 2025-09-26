import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

for _module_name in [
    name for name in list(sys.modules) if name == "fido2" or name.startswith("fido2.")
]:
    del sys.modules[_module_name]

from fido2 import cose


def _int_to_bytes(value: int) -> bytes:
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length or 1, "big")


def _build_rsa_cose_key(private_key: rsa.RSAPrivateKey, alg: int) -> cose.CoseKey:
    public_numbers = private_key.public_key().public_numbers()
    cose_map = {
        1: 3,  # kty: RSA
        3: alg,
        -1: _int_to_bytes(public_numbers.n),
        -2: _int_to_bytes(public_numbers.e),
    }
    return cose.CoseKey.parse(cose_map)


@pytest.mark.parametrize(
    "alg, signer",
    [
        (
            -257,
            lambda key, message: key.sign(
                message, padding.PKCS1v15(), hashes.SHA256()
            ),
        ),
        (
            -258,
            lambda key, message: key.sign(
                message, padding.PKCS1v15(), hashes.SHA384()
            ),
        ),
        (
            -259,
            lambda key, message: key.sign(
                message, padding.PKCS1v15(), hashes.SHA512()
            ),
        ),
    ],
)
def test_pkcs1_algorithms_verify_signatures(alg, signer):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"pkcs1 message"
    cose_key = _build_rsa_cose_key(private_key, alg)

    signature = signer(private_key, message)
    cose_key.verify(message, signature)

    with pytest.raises(Exception):
        cose_key.verify(message, b"\x00" * len(signature))


@pytest.mark.parametrize(
    "alg, hash_cls",
    [
        (-37, hashes.SHA256),
        (-38, hashes.SHA384),
        (-39, hashes.SHA512),
    ],
)
def test_pss_algorithms_verify_signatures(alg, hash_cls):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"pss message"
    cose_key = _build_rsa_cose_key(private_key, alg)

    hash_alg = hash_cls()
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
        hash_alg,
    )

    cose_key.verify(message, signature)

    with pytest.raises(Exception):
        cose_key.verify(message, b"\xff" * len(signature))
