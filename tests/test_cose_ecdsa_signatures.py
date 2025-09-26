from __future__ import annotations
from typing import Type

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

from fido2.cose import ES256, ES256K, ES384, ES512, CoseKey


def _raw_signature_from_der(signature: bytes, coordinate_length: int) -> bytes:
    r, s = decode_dss_signature(signature)
    return r.to_bytes(coordinate_length, "big") + s.to_bytes(coordinate_length, "big")


def _exercise_raw_signature(
    cose_cls: Type[CoseKey],
    curve: ec.EllipticCurve,
    hash_algorithm_cls: Type[hashes.HashAlgorithm],
) -> None:
    private_key = ec.generate_private_key(curve)
    message = b"ecdsa-message"
    signature = private_key.sign(message, ec.ECDSA(hash_algorithm_cls()))
    public_key = private_key.public_key()
    coordinate_length = (public_key.curve.key_size + 7) // 8
    raw_signature = _raw_signature_from_der(signature, coordinate_length)
    cose_key = cose_cls.from_cryptography_key(public_key)
    cose_key.verify(message, raw_signature)


def test_es256_accepts_raw_signatures() -> None:
    _exercise_raw_signature(ES256, ec.SECP256R1(), hashes.SHA256)


def test_es384_accepts_raw_signatures() -> None:
    _exercise_raw_signature(ES384, ec.SECP384R1(), hashes.SHA384)


def test_es512_accepts_raw_signatures() -> None:
    _exercise_raw_signature(ES512, ec.SECP521R1(), hashes.SHA512)


def test_es256k_accepts_raw_signatures() -> None:
    _exercise_raw_signature(ES256K, ec.SECP256K1(), hashes.SHA256)
