"""Whether a credential's COSE public key can be used: its key type is its algorithm's, its
curve is the one its algorithm names (WebAuthn L3 section 5.8.5), and it loads into a key
``cryptography`` can verify with -- an EC2 point on its curve, an OKP or ML-DSA key of its
length, an RSA key whose numbers are one. A key that cannot be used is ``cose_key_invalid``
with why; one that does not read at all is ``response_checks``' ``cose_key_error``. An RSA
key whose modulus is under 2048 bits can be used, and is a warning.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa

from . import error_codes

# COSE key types (RFC 9052 section 7; AKP for ML-DSA).
_KEY_TYPES = {1: "OKP", 2: "EC2", 3: "RSA", 7: "AKP"}

# Each EC2 algorithm's curve: its COSE crv, its name, and cryptography's curve. ES256,
# ES384 and ES512 must name it (L3 section 5.8.5); the ESP algorithms and ES256K are
# fully specified by it.
_EC2_CURVES: dict[int, tuple[int, str, ec.EllipticCurve]] = {
    -7: (1, "P-256", ec.SECP256R1()),
    -9: (1, "P-256", ec.SECP256R1()),
    -35: (2, "P-384", ec.SECP384R1()),
    -51: (2, "P-384", ec.SECP384R1()),
    -36: (3, "P-521", ec.SECP521R1()),
    -52: (3, "P-521", ec.SECP521R1()),
    -47: (8, "secp256k1", ec.SECP256K1()),
}

# Each OKP algorithm's curve. EdDSA (-8) must name Ed25519 (L3 section 5.8.5), the only
# curve fido2 verifies it with; Ed448 is -53's.
_OKP_CURVES: dict[int, tuple[int, str, Any]] = {
    -8: (6, "Ed25519", ed25519.Ed25519PublicKey),
    -19: (6, "Ed25519", ed25519.Ed25519PublicKey),
    -53: (7, "Ed448", ed448.Ed448PublicKey),
}

_RSA_ALGORITHMS = frozenset({-257, -258, -259, -37, -38, -39, -65535})
# Below this an RSA key is a warning (NIST SP 800-131A).
MIN_RSA_MODULUS_BITS = 2048

_MLDSA_KEYS: dict[int, Any] = {
    -48: mldsa.MLDSA44PublicKey,
    -49: mldsa.MLDSA65PublicKey,
    -50: mldsa.MLDSA87PublicKey,
}


def _is(value: Any, expected: int) -> bool:
    """Whether ``value`` is the integer ``expected`` (a CBOR true is not 1)."""

    return not isinstance(value, bool) and value == expected


def _curve_problem(alg: int, crv: Any, expected: int, name: str) -> str | None:
    if _is(crv, expected):
        return None
    return f"crv {crv!r} is not {name} ({expected}), the curve of COSE algorithm {alg}"


def _ec2_problem(alg: int, key: Mapping[Any, Any]) -> str | None:
    crv, name, curve = _EC2_CURVES[alg]
    problem = _curve_problem(alg, key.get(-1), crv, name)
    if problem is not None:
        return problem
    x, y = key.get(-2), key.get(-3)
    if isinstance(y, bool):
        # L3 section 5.8.5: these keys MUST NOT use the compressed point form.
        return "the point is in compressed form"
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        return "the point's coordinates are not byte strings"
    try:
        ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve).public_key()
    except ValueError:
        return f"the point is not on {name}"
    return None


def _okp_problem(alg: int, key: Mapping[Any, Any]) -> str | None:
    crv, name, key_type = _OKP_CURVES[alg]
    problem = _curve_problem(alg, key.get(-1), crv, name)
    if problem is not None:
        return problem
    public_key = key.get(-2)
    if not isinstance(public_key, bytes):
        return "the public key is not a byte string"
    try:
        key_type.from_public_bytes(public_key)
    except ValueError as exc:
        return str(exc)
    return None


def _rsa_problem(alg: int, key: Mapping[Any, Any]) -> str | None:
    modulus, exponent = key.get(-1), key.get(-2)
    if not isinstance(modulus, bytes) or not isinstance(exponent, bytes):
        return "the modulus or the exponent is not a byte string"
    try:
        rsa.RSAPublicNumbers(int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")).public_key()
    except ValueError as exc:
        return str(exc)
    return None


def _mldsa_problem(alg: int, key: Mapping[Any, Any]) -> str | None:
    public_key = key.get(-1)
    if not isinstance(public_key, bytes):
        return "the public key is not a byte string"
    try:
        _MLDSA_KEYS[alg].from_public_bytes(public_key)
    except ValueError as exc:
        return str(exc)
    return None


def _family(alg: Any) -> tuple[int, Callable[[int, Mapping[Any, Any]], str | None]] | None:
    """The key type an algorithm's keys have, and the check of the rest; None for one this server does not use."""

    if not isinstance(alg, int) or isinstance(alg, bool):
        return None
    if alg in _EC2_CURVES:
        return 2, _ec2_problem
    if alg in _OKP_CURVES:
        return 1, _okp_problem
    if alg in _RSA_ALGORITHMS:
        return 3, _rsa_problem
    if alg in _MLDSA_KEYS:
        return 7, _mldsa_problem
    return None


def key_problem(cose_key: Mapping[Any, Any]) -> str | None:
    """Why ``cose_key`` cannot be used for the algorithm it names, or None when it can."""

    alg = cose_key.get(3)
    family = _family(alg)
    if family is None:
        return f"COSE algorithm {alg!r} is not one this server can use"
    kty, check = family
    if not _is(cose_key.get(1), kty):
        return f"kty {cose_key.get(1)!r} is not {_KEY_TYPES[kty]} ({kty}), the key type of COSE algorithm {alg}"
    return check(alg, cose_key)


def key_findings(cose_key: Mapping[Any, Any]) -> tuple[list[str], list[str]]:
    """The errors and warnings of a credential's COSE key: ``cose_key_invalid`` and why, or
    the warning of a usable RSA key whose modulus is under ``MIN_RSA_MODULUS_BITS``."""

    problem = key_problem(cose_key)
    if problem is not None:
        return [error_codes.invalid_cose_key(problem)], []
    if cose_key.get(3) in _RSA_ALGORITHMS:
        bits = int.from_bytes(cose_key[-1], "big").bit_length()
        if bits < MIN_RSA_MODULUS_BITS:
            return [], [error_codes.short_rsa_modulus(bits)]
    return [], []
