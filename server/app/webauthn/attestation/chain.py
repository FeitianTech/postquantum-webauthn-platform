"""Certificate chain signatures, ML-DSA included.

fido2's ``verify_x509_chain`` verifies RSA (PKCS#1 v1.5) and ECDSA issuers only.
This is its walk with cryptography's ``verify_directly_issued_by`` for each link,
which also verifies RSA-PSS, EdDSA and ML-DSA signatures and checks that the
issuer's name is the one the certificate names: each certificate is checked
against the next, the leaf first and the root last.
"""
from __future__ import annotations

from collections.abc import Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from fido2.attestation import InvalidSignature

from ..mldsa import PUBLIC_KEY_TYPES, describe_mldsa_oid

__all__ = ["verify_certificate_chain", "verify_mldsa_certificate_signature"]


def _verify_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    try:
        issuer.public_key()
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError(f"Unsupported issuer key: {exc}") from None
    try:
        child.verify_directly_issued_by(issuer)
    except (_InvalidSignature, ValueError):
        # A signature that does not verify, a name that is not the issuer's, or a
        # signature of another key type: the certificate was not issued by it.
        raise InvalidSignature() from None


def verify_certificate_chain(chain: Sequence[bytes]) -> None:
    """Check that each DER certificate in ``chain`` is signed by the next.

    Raises fido2's ``InvalidSignature`` for a certificate the next did not issue and
    ``ValueError`` for a certificate that does not parse or an issuer key that does
    not load.
    """

    certificates = [x509.load_der_x509_certificate(bytes(der)) for der in chain]
    for child, issuer in zip(certificates, certificates[1:]):
        _verify_issued_by(child, issuer)


def verify_mldsa_certificate_signature(child_der: bytes, issuer_der: bytes) -> None:
    """Check that ``issuer_der``'s ML-DSA key signed ``child_der``, with the same parameter set.

    Every failure, including input that does not parse, is fido2's ``InvalidSignature``.
    """

    try:
        child = x509.load_der_x509_certificate(child_der)
    except Exception as exc:
        raise InvalidSignature(f"Unable to parse ML-DSA certificate: {exc}") from exc

    signature_oid = child.signature_algorithm_oid.dotted_string
    if not describe_mldsa_oid(signature_oid):
        raise InvalidSignature(f"Unsupported signature algorithm OID for ML-DSA verification: {signature_oid}")

    try:
        issuer = x509.load_der_x509_certificate(issuer_der)
        public_key = issuer.public_key()
    except Exception as exc:
        raise InvalidSignature(f"Unable to parse issuer public key: {exc}") from exc

    if not isinstance(public_key, PUBLIC_KEY_TYPES):
        raise InvalidSignature(f"Issuer public key is not an ML-DSA key: {type(public_key).__name__}")

    issuer_key_oid = issuer.public_key_algorithm_oid.dotted_string
    if issuer_key_oid != signature_oid:
        raise InvalidSignature(
            "Issuer ML-DSA parameter set does not match the certificate signature "
            f"algorithm ({issuer_key_oid} != {signature_oid})"
        )

    try:
        public_key.verify(child.signature, child.tbs_certificate_bytes)
    except _InvalidSignature as exc:
        raise InvalidSignature("ML-DSA certificate signature verification failed") from exc
