"""One line of facts about an X.509 certificate, read with ``cryptography``.

The decoder's full certificate view is ``serialize_attestation_certificate``;
this is the short form the attestation views list a chain in.
"""
from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def summarize(der: Any) -> dict[str, Any]:
    if not isinstance(der, bytes):
        return {"error": "a certificate in x5c is a byte string of DER; this is not"}
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return {"error": f"not an X.509 certificate: {exc}"}
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "notValidBefore": certificate.not_valid_before_utc.isoformat(),
        "notValidAfter": certificate.not_valid_after_utc.isoformat(),
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
    }
