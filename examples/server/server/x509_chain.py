"""Server-specific X.509 chain verification utilities."""
from __future__ import annotations

from typing import Any, List, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from fido2.attestation.base import (
    EC_PUBLIC_KEY_OIDS,
    InvalidSignature,
    MLDSA_OIDS,
    RSA_PUBLIC_KEY_OIDS,
    SIGNATURE_ALGORITHM_OIDS,
    _get_parsed_certificate,
    _hash_for_signature_oid,
    _verify_mldsa_certificate_signature,
    set_x509_chain_verifier,
)
from fido2.utils import ByteBuffer


MLDSA_PUBLIC_KEY_OIDS = set(MLDSA_OIDS)


def _coerce_der_bytes(value: Any) -> bytes:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        "Certificate chain entries must be DER-encoded bytes, "
        f"not {type(value).__name__}"
    )


def _server_verify_x509_chain(chain: Sequence[bytes]) -> None:
    if not chain:
        return

    remaining: List[bytes] = [_coerce_der_bytes(cert) for cert in chain]
    child_der = remaining.pop(0)

    while remaining:
        issuer_der = remaining.pop(0)
        child_parsed = _get_parsed_certificate(child_der)
        child_signature_oid = child_parsed.signature_algorithm_oid
        print(
            "server verify_x509_chain: cached child signatureAlgorithm OID from DER",
            child_signature_oid,
        )
        signature_class = SIGNATURE_ALGORITHM_OIDS.get(child_signature_oid)
        if signature_class is None:
            raise ValueError(f"Unsupported signature algorithm OID: {child_signature_oid}")
        print(
            "server verify_x509_chain: classified child signature algorithm",
            signature_class,
        )

        issuer_parsed = _get_parsed_certificate(issuer_der)
        issuer_spki_oid = issuer_parsed.subject_public_key_algorithm_oid
        issuer_public_key = issuer_parsed.subject_public_key
        print(
            "server verify_x509_chain: cached issuer SubjectPublicKeyInfo algorithm OID",
            issuer_spki_oid,
        )

        try:
            if signature_class == "MLDSA":
                print(
                    "server verify_x509_chain: using ML-DSA verifier for signature OID",
                    child_signature_oid,
                )
                if issuer_spki_oid not in MLDSA_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match ML-DSA parameter set"
                    )
                print(
                    "server verify_x509_chain: issuer SPKI recognized as ML-DSA OID",
                    issuer_spki_oid,
                )
                _verify_mldsa_certificate_signature(
                    child_parsed.tbs_certificate,
                    child_parsed.signature_value,
                    issuer_public_key,
                    child_signature_oid,
                )
            elif signature_class == "RSA":
                if issuer_spki_oid not in RSA_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match RSA algorithm"
                    )
                print(
                    "server verify_x509_chain: issuer SPKI recognized as RSA OID",
                    issuer_spki_oid,
                )
                print(
                    "server verify_x509_chain: using RSA verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(
                    issuer_der, default_backend()
                )
                pub = issuer_cert.public_key()
                if not isinstance(pub, rsa.RSAPublicKey):
                    raise ValueError("Issuer public key is not RSA")
                print(
                    "server verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
                child_cert_for_debug = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "server verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                pub.verify(
                    child_parsed.signature_value,
                    child_parsed.tbs_certificate,
                    padding.PKCS1v15(),
                    hash_algorithm,
                )
            elif signature_class == "EC":
                if issuer_spki_oid not in EC_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match EC algorithm"
                    )
                print(
                    "server verify_x509_chain: issuer SPKI recognized as EC OID",
                    issuer_spki_oid,
                )
                print(
                    "server verify_x509_chain: using EC verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(
                    issuer_der, default_backend()
                )
                pub = issuer_cert.public_key()
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    raise ValueError("Issuer public key is not EC")
                print(
                    "server verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
                child_cert_for_debug = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "server verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                pub.verify(
                    child_parsed.signature_value,
                    child_parsed.tbs_certificate,
                    ec.ECDSA(hash_algorithm),
                )
            else:  # pragma: no cover - exhaustive safeguard
                raise ValueError(
                    f"Unhandled signature classification for OID: {child_signature_oid}"
                )
        except _InvalidSignature:
            raise InvalidSignature()

        child_der = issuer_der


set_x509_chain_verifier(_server_verify_x509_chain)


def verify_x509_chain(chain: Sequence[bytes]) -> None:
    """Expose the server-specific verifier for direct use in tests."""

    _server_verify_x509_chain(chain)


__all__ = [
    "MLDSA_OIDS",
    "MLDSA_PUBLIC_KEY_OIDS",
    "SIGNATURE_ALGORITHM_OIDS",
    "verify_x509_chain",
]
