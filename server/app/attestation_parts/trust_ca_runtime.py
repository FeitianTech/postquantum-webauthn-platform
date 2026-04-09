from __future__ import annotations

import hashlib
from typing import Optional, Set


def _trusted_ca_subjects() -> Optional[Set[str]]:
    subjects = app.config.get("TRUSTED_ATTESTATION_CA_SUBJECTS")
    if isinstance(subjects, set):
        return subjects
    if isinstance(subjects, (list, tuple)):
        return {str(subject) for subject in subjects if subject}
    return None


def _trusted_ca_fingerprints() -> Optional[Set[str]]:
    fingerprints = app.config.get("TRUSTED_ATTESTATION_CA_FINGERPRINTS")
    if isinstance(fingerprints, set):
        return {str(fp).upper() for fp in fingerprints if fp}
    if isinstance(fingerprints, (list, tuple)):
        return {str(fp).upper() for fp in fingerprints if fp}
    return None


def _certificate_fingerprint(cert_bytes: bytes) -> str:
    return hashlib.sha256(cert_bytes).hexdigest().upper()


def _is_trusted_ca_certificate(cert_bytes: bytes, *, allow_subject_parsing: bool = True) -> bool:
    subjects = _trusted_ca_subjects()
    fingerprints = _trusted_ca_fingerprints()

    if not subjects and not fingerprints:
        return True

    if fingerprints:
        fingerprint = _certificate_fingerprint(cert_bytes)
        if fingerprint in fingerprints:
            return True

    if allow_subject_parsing and subjects:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
        except Exception:
            return False
        subject_value = cert.subject.rfc4514_string()
        if subject_value in subjects:
            return True

    return False
