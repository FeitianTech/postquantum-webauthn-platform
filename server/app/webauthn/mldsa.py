"""ML-DSA in X.509 certificates: parameter sets, their FIPS 204 sizes, and what a certificate declares.

``cryptography`` parses and verifies ML-DSA certificates; what this module adds
is the naming the attestation views and the decoder show: which parameter set an
algorithm OID means, the sizes FIPS 204 gives it, and a certificate's public key
as the raw bytes a COSE key carries.
"""
from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa

__all__ = [
    "PUBLIC_KEY_TYPES",
    "describe_mldsa_oid",
    "describe_mldsa_oid_name",
    "extract_certificate_public_key_info",
    "parameter_details",
]

_OID_TO_PARAMETER_SET: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

# FIPS 204 (final) sizes. The pre-standard CRYSTALS-Dilithium Round 3 signature
# sizes were 2420/3293/4595; FIPS 204 widened the challenge seed for the two
# higher parameter sets, which added 16 and 32 bytes respectively.
_PARAMETER_SET_DETAILS: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"public_key_length": 1312, "signature_length": 2420, "claimed_nist_level": 2},
    "ML-DSA-65": {"public_key_length": 1952, "signature_length": 3309, "claimed_nist_level": 3},
    "ML-DSA-87": {"public_key_length": 2592, "signature_length": 4627, "claimed_nist_level": 5},
}

# Usable with isinstance() to recognise any ML-DSA public key.
PUBLIC_KEY_TYPES: tuple[type, ...] = (
    mldsa.MLDSA44PublicKey,
    mldsa.MLDSA65PublicKey,
    mldsa.MLDSA87PublicKey,
)


def parameter_details(parameter_set: str | None) -> dict[str, int]:
    """The FIPS 204 lengths for ``parameter_set``; empty for anything else."""

    if not parameter_set:
        return {}
    return dict(_PARAMETER_SET_DETAILS.get(parameter_set, {}))


def describe_mldsa_oid(oid: str | None) -> dict[str, str] | None:
    """What an ML-DSA certificate algorithm OID names, or None for any other OID."""

    parameter_set = _OID_TO_PARAMETER_SET.get(oid) if oid else None
    if parameter_set is None:
        return None
    return {"name": "ML-DSA", "mlDsaParameterSet": parameter_set, "display": parameter_set, "oid": oid}


def describe_mldsa_oid_name(oid: str | None) -> str | None:
    """The parameter set's name for a recognised ML-DSA OID."""

    details = describe_mldsa_oid(oid)
    return details["display"] if details is not None else None


def _subject_public_key_bytes(public_key: Any) -> bytes | None:
    """The SubjectPublicKey BIT STRING payload for a parsed public key."""

    if isinstance(public_key, PUBLIC_KEY_TYPES):
        return public_key.public_bytes_raw()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    try:
        return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception:
        return None


def extract_certificate_public_key_info(cert_der: bytes) -> dict[str, Any]:
    """A certificate's public key algorithm and key, and for ML-DSA its parameter set.

    Raises ``ValueError`` for anything that is not a DER certificate.
    """

    certificate = x509.load_der_x509_certificate(bytes(cert_der))
    algorithm_oid = certificate.public_key_algorithm_oid.dotted_string
    info: dict[str, Any] = {"algorithm_oid": algorithm_oid, "algorithm_parameters": None}

    try:
        public_key = certificate.public_key()
    except (UnsupportedAlgorithm, ValueError):
        # A key algorithm cryptography cannot parse: report what the certificate
        # declares and leave the key material out rather than guess at it.
        public_key = None
    if public_key is not None:
        info["subject_public_key_info"] = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        subject_public_key = _subject_public_key_bytes(public_key)
        if subject_public_key is not None:
            info["subject_public_key"] = subject_public_key

    details = describe_mldsa_oid(algorithm_oid)
    if details is not None:
        parameter_set = details["mlDsaParameterSet"]
        info["ml_dsa_parameter_set"] = parameter_set
        info["ml_dsa_parameter_details"] = parameter_details(parameter_set)
        info["algorithm_name"] = details["name"]
        info["algorithm_display_name"] = details["display"]
    return info
