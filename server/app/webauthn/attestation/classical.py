from __future__ import annotations

from datetime import datetime
from typing import Any, NamedTuple

from cryptography import x509
from fido2.attestation import InvalidSignature

from ...mds import verifier as mds_verifier
from . import evaluation, trust
from .chain import verify_certificate_chain


class _MetadataEvaluation(NamedTuple):
    trust_details: evaluation.TrustPathEvaluation | None
    entry: Any | None
    lookup_source: str | None
    unavailable: bool


def _evaluate_classical_attestation_root(
    attestation_object: Any,
    attestation_result: Any,
    client_data_hash: bytes,
    verifier: Any | None,
    now: datetime,
) -> dict[str, Any]:
    """Evaluate attestation trust using classical x509 verification.

    Each stage adds its errors in turn: the chain's signatures, the
    certificates' dates, the metadata evaluation, then the root and FIDO trust.
    """

    warnings: list[str] = []
    errors: list[str] = []
    checks: dict[str, bool | None] = {
        "trusted_ca": None,
        "chain": None,
        "fido_mds": None,
    }

    trust_path = list(getattr(attestation_result, "trust_path", []) or [])
    manual_chain_valid = _verify_trust_path(trust_path, errors)
    chain_valid_dates = _trust_path_dates_valid(trust_path, now, errors)
    metadata = _evaluate_with_metadata(verifier, attestation_object, client_data_hash, warnings, errors)

    trusted_ca = _trusted_ca(metadata, errors)
    checks["trusted_ca"] = trusted_ca

    if trusted_ca is True and metadata.entry is not None:
        fido_status = mds_verifier.metadata_entry_trust_anchor_status(metadata.entry)
        if fido_status is True:
            checks["fido_mds"] = True
        elif fido_status is False:
            checks["fido_mds"] = False
            errors.append("metadata_not_fido_trusted")

    chain_valid = _chain_valid(metadata.trust_details, manual_chain_valid, chain_valid_dates)
    if trusted_ca is True:
        checks["chain"] = chain_valid

    return {
        "root_valid": trust._resolve_root_validity(checks),
        "metadata_entry": metadata.entry,
        "metadata_lookup_source": metadata.lookup_source,
        "warnings": warnings,
        "errors": errors,
        "checks": checks,
    }


def _verify_trust_path(trust_path: list[Any], errors: list[str]) -> bool | None:
    """Whether the chain's signatures verify; ``None`` without a chain."""

    if not trust_path:
        errors.append("trust_path_missing")
        return None
    try:
        verify_certificate_chain(trust_path)
    except InvalidSignature:
        return False
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"certificate_chain_error: {exc}")
        return False
    return True


def _trust_path_dates_valid(trust_path: list[Any], now: datetime, errors: list[str]) -> bool:
    chain_valid_dates = True
    for cert_der in trust_path:
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            errors.append(f"certificate_parse_error: {exc}")
            chain_valid_dates = False
            continue

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if now < not_before or now > not_after:
            chain_valid_dates = False
            errors.append(f"certificate_out_of_validity: {_subject_text(cert)}")
    return chain_valid_dates


def _subject_text(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except (TypeError, ValueError):
        # cryptography reads a name only when asked, and refuses one it cannot
        # type (a common name that is not a string).
        return "a subject that cannot be read"


def _evaluate_with_metadata(
    verifier: Any | None,
    attestation_object: Any,
    client_data_hash: bytes,
    warnings: list[str],
    errors: list[str],
) -> _MetadataEvaluation:
    """The attestation evaluated against the MDS metadata, when there is a verifier."""

    if verifier is None:
        warnings.append("metadata_not_available")
        return _MetadataEvaluation(None, None, None, True)
    try:
        outcome = evaluation.evaluate_attestation(
            verifier, attestation_object, client_data_hash
        )
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"untrusted_attestation: {exc}")
        return _MetadataEvaluation(None, None, None, False)
    trust_details = outcome.trust_path
    if trust_details.errors:
        errors.extend(trust_details.errors)
    return _MetadataEvaluation(trust_details, outcome.metadata_entry, outcome.metadata_lookup_source, False)


def _trusted_ca(metadata: _MetadataEvaluation, errors: list[str]) -> bool:
    """Whether a root the attestation or its metadata names is a trusted CA."""

    candidate_roots: list[bytes] = []
    if metadata.trust_details is not None and metadata.trust_details.ca_certificate:
        candidate_roots.append(metadata.trust_details.ca_certificate)
    if metadata.entry is not None:
        candidate_roots.extend(trust._collect_metadata_root_certificates(metadata.entry))
    elif not metadata.unavailable:
        errors.append("metadata_entry_missing")

    trusted_roots = [
        root for root in candidate_roots if trust._is_trusted_ca_certificate(root)
    ]

    if trusted_roots:
        return True
    if candidate_roots:
        errors.append("attestation_root_not_trusted")
    return False


def _chain_valid(
    trust_details: evaluation.TrustPathEvaluation | None, manual_chain_valid: bool | None, chain_valid_dates: bool
) -> bool | None:
    """The metadata evaluation's chain verdict, else the chain's own, made false by a bad date."""

    chain_valid: bool | None = None
    if trust_details is not None:
        chain_valid = trust_details.chain_valid
    if chain_valid is None:
        chain_valid = manual_chain_valid
    if chain_valid is True and not chain_valid_dates:
        chain_valid = False
    # No verdict comes only from an empty trust path, whose dates are never bad.
    return chain_valid
