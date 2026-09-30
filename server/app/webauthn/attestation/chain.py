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

__all__ = ["verify_certificate_chain"]


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
