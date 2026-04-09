from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


def _evaluate_classical_attestation_root(
    attestation_object: Any,
    attestation_result: Any,
    client_data_hash: bytes,
    verifier: Optional[Any],
    now: datetime,
) -> Dict[str, Any]:
    """Evaluate attestation trust using classical x509 verification."""

    warnings: List[str] = []
    errors: List[str] = []
    metadata_entry: Optional[Any] = None
    metadata_lookup_source: Optional[str] = None
    checks: Dict[str, Optional[bool]] = {
        "trusted_ca": None,
        "chain": None,
        "fido_mds": None,
    }

    trust_path = list(getattr(attestation_result, "trust_path", []) or [])

    manual_chain_valid: Optional[bool] = None
    if trust_path:
        manual_chain_valid = True
        try:
            verify_x509_chain(list(trust_path))
        except InvalidSignature:
            manual_chain_valid = False
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"certificate_chain_error: {exc}")
            manual_chain_valid = False
    else:
        errors.append("trust_path_missing")

    chain_valid_dates = True
    for cert_der in trust_path:
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            errors.append(f"certificate_parse_error: {exc}")
            chain_valid_dates = False
            continue

        not_before = _certificate_datetime(cert, "not_valid_before")
        not_after = _certificate_datetime(cert, "not_valid_after")
        if now < not_before or now > not_after:
            chain_valid_dates = False
            errors.append(
                f"certificate_out_of_validity: {cert.subject.rfc4514_string()}"
            )

    trust_details: Optional[TrustPathEvaluation] = None

    metadata_unavailable = False
    if verifier is None:
        metadata_unavailable = True
        warnings.append("metadata_not_available")
    else:
        try:
            evaluation = verifier.evaluate_attestation(
                attestation_object, client_data_hash
            )
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"untrusted_attestation: {exc}")
        else:
            trust_details = evaluation.trust_path
            metadata_entry = evaluation.metadata_entry
            metadata_lookup_source = evaluation.metadata_lookup_source
            if trust_details.errors:
                errors.extend(trust_details.errors)

    candidate_roots: List[bytes] = []
    if trust_details is not None and trust_details.ca_certificate:
        candidate_roots.append(trust_details.ca_certificate)
    if metadata_entry is not None:
        candidate_roots.extend(_collect_metadata_root_certificates(metadata_entry))
    elif not metadata_unavailable:
        errors.append("metadata_entry_missing")

    trusted_roots = [
        root for root in candidate_roots if _is_trusted_ca_certificate(root)
    ]

    trusted_ca: Optional[bool]
    if trusted_roots:
        trusted_ca = True
    elif candidate_roots:
        trusted_ca = False
        errors.append("attestation_root_not_trusted")
    else:
        trusted_ca = False

    checks["trusted_ca"] = trusted_ca

    if trusted_ca is True and metadata_entry is not None:
        fido_status = metadata_entry_trust_anchor_status(metadata_entry)
        if fido_status is True:
            checks["fido_mds"] = True
        elif fido_status is False:
            checks["fido_mds"] = False
            errors.append("metadata_not_fido_trusted")

    chain_valid: Optional[bool] = None
    if trust_details is not None:
        chain_valid = trust_details.chain_valid
    if chain_valid is None:
        chain_valid = manual_chain_valid
    if chain_valid is True and not chain_valid_dates:
        chain_valid = False
    if chain_valid is None and chain_valid_dates is False:
        chain_valid = False
    if trusted_ca is True:
        checks["chain"] = chain_valid

    return {
        "root_valid": _resolve_root_validity(checks),
        "metadata_entry": metadata_entry,
        "metadata_lookup_source": metadata_lookup_source,
        "warnings": warnings,
        "errors": errors,
        "checks": checks,
    }
