"""``webauthn.attestation.public_key_checks``: whether a credential's COSE key can be used for its algorithm."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa
from fido2.cose import ES256, ES256K, ES384, ES512, RS256, Ed448, Ed25519, EdDSA

from server.app.webauthn.attestation import public_key_checks

_P256 = ES256.from_cryptography_key(ec.generate_private_key(ec.SECP256R1()).public_key())
_ED25519 = EdDSA.from_cryptography_key(ed25519.Ed25519PrivateKey.generate().public_key())
_RSA = RS256.from_cryptography_key(rsa.generate_private_key(65537, 2048).public_key())


def _mldsa(alg: int, private_key) -> dict:
    return {1: 7, 3: alg, -1: private_key.public_key().public_bytes_raw()}


@pytest.mark.parametrize(
    "cose_key",
    [
        _P256,
        {**_P256, 3: -9},
        ES384.from_cryptography_key(ec.generate_private_key(ec.SECP384R1()).public_key()),
        ES512.from_cryptography_key(ec.generate_private_key(ec.SECP521R1()).public_key()),
        ES256K.from_cryptography_key(ec.generate_private_key(ec.SECP256K1()).public_key()),
        _ED25519,
        Ed25519.from_cryptography_key(ed25519.Ed25519PrivateKey.generate().public_key()),
        Ed448.from_cryptography_key(ed448.Ed448PrivateKey.generate().public_key()),
        _RSA,
        {**_RSA, 3: -37},
        _mldsa(-48, mldsa.MLDSA44PrivateKey.generate()),
        _mldsa(-49, mldsa.MLDSA65PrivateKey.generate()),
        _mldsa(-50, mldsa.MLDSA87PrivateKey.generate()),
    ],
    ids=lambda key: f"alg {key[3]}",
)
def test_a_key_of_each_algorithm_that_loads_can_be_used(cose_key):
    assert public_key_checks.key_problem(cose_key) is None
    assert public_key_checks.key_findings(cose_key) == ([], [])


@pytest.mark.parametrize(
    ("cose_key", "problem"),
    [
        ({**_P256, -1: 2}, "crv 2 is not P-256 (1), the curve of COSE algorithm -7"),
        ({**_P256, 3: -35}, "crv 1 is not P-384 (2), the curve of COSE algorithm -35"),
        ({**_P256, 3: -47}, "crv 1 is not secp256k1 (8), the curve of COSE algorithm -47"),
        ({**_P256, -1: True}, "crv True is not P-256 (1), the curve of COSE algorithm -7"),
        ({**_P256, -2: b"\x01" * 32, -3: b"\x02" * 32}, "the point is not on P-256"),
        ({**_P256, -3: True}, "the point is in compressed form"),
        ({**_P256, -3: "y"}, "the point's coordinates are not byte strings"),
        ({**_ED25519, -1: 7}, "crv 7 is not Ed25519 (6), the curve of COSE algorithm -8"),
        ({**_ED25519, 3: -19, -1: 7}, "crv 7 is not Ed25519 (6), the curve of COSE algorithm -19"),
        ({**_ED25519, 3: -53}, "crv 6 is not Ed448 (7), the curve of COSE algorithm -53"),
        ({**_ED25519, -2: b"\x01" * 31}, "An Ed25519 public key is 32 bytes long"),
        ({**_ED25519, -2: None}, "the public key is not a byte string"),
        ({**_RSA, -2: b"\x02"}, "e must be >= 3 and < n."),
        ({**_RSA, -1: 5}, "the modulus or the exponent is not a byte string"),
        ({1: 7, 3: -48, -1: b"\x01" * 1311}, "An ML-DSA-44 public key is 1312 bytes long"),
        ({1: 7, 3: -49, -1: b"\x01" * 1312}, "An ML-DSA-65 public key is 1952 bytes long"),
        ({1: 7, 3: -50}, "the public key is not a byte string"),
        ({**_P256, 1: 3}, "kty 3 is not EC2 (2), the key type of COSE algorithm -7"),
        ({**_ED25519, 1: 2}, "kty 2 is not OKP (1), the key type of COSE algorithm -8"),
        ({**_RSA, 1: True}, "kty True is not RSA (3), the key type of COSE algorithm -257"),
        ({1: 2, 3: -48, -1: b"\x01" * 1312}, "kty 2 is not AKP (7), the key type of COSE algorithm -48"),
        ({**_P256, 3: -12345}, "COSE algorithm -12345 is not one this server can use"),
        ({**_P256, 3: "ES256"}, "COSE algorithm 'ES256' is not one this server can use"),
        ({**_P256, 3: True}, "COSE algorithm True is not one this server can use"),
        ({**_P256, 3: [-7]}, "COSE algorithm [-7] is not one this server can use"),
    ],
)
def test_a_key_that_cannot_be_used_says_why(cose_key, problem):
    assert public_key_checks.key_problem(cose_key) == problem
    assert public_key_checks.key_findings(cose_key) == ([f"cose_key_invalid: {problem}"], [])


def test_an_rsa_key_under_2048_bits_can_be_used_and_is_a_warning():
    short = RS256.from_cryptography_key(rsa.generate_private_key(65537, 1024).public_key())
    odd_size = {**_RSA, -1: (int.from_bytes(_RSA[-1], "big") >> 1).to_bytes(256, "big")}

    assert public_key_checks.key_findings(short) == ([], ["rsa_modulus_too_short: 1024 bits"])
    assert public_key_checks.key_findings({**short, 3: -37}) == ([], ["rsa_modulus_too_short: 1024 bits"])
    assert public_key_checks.key_findings(odd_size) == ([], ["rsa_modulus_too_short: 2047 bits"])
