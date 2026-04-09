from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional


def _resolve_signature_validation(
    attestation_object: Any,
    client_data_hash: bytes,
) -> Dict[str, Any]:
    attestation_format_value = (attestation_object.fmt or "").lower()
    attestation_result = None
    attestation_errors: List[str] = []

    if attestation_format_value == "none":
        signature_valid = None
    else:
        try:
            attestation_cls = Attestation.for_type(attestation_object.fmt)
            attestation_instance = attestation_cls()
            attestation_result = attestation_instance.verify(
                attestation_object.att_stmt,
                attestation_object.auth_data,
                client_data_hash,
            )
            signature_valid = True
        except UnsupportedType as exc:
            attestation_errors.append(f"unsupported_attestation: {exc}")
            signature_valid = False
        except (InvalidSignature, InvalidData) as exc:
            attestation_errors.append(f"attestation_invalid: {exc}")
            signature_valid = False
        except Exception as exc:
            attestation_errors.append(f"attestation_error: {exc}")
            signature_valid = False

    if signature_valid is False and attestation_format_value != "none":
        pqc_outcome = _attempt_pqc_attestation_signature_validation(
            attestation_object, client_data_hash
        )
        if pqc_outcome.get("attempted"):
            pqc_error = pqc_outcome.get("error")
            if pqc_outcome.get("success"):
                signature_valid = True
                attestation_result = pqc_outcome.get("attestation_result")
                attestation_errors = []
            elif pqc_error:
                attestation_errors.append(str(pqc_error))

    return {
        "attestation_format_value": attestation_format_value,
        "signature_valid": signature_valid,
        "attestation_result": attestation_result,
        "attestation_errors": attestation_errors,
    }


def _collect_attestation_trust_path(
    attestation_result: Any,
    attestation_object: Any,
) -> List[bytes]:
    attestation_trust_path: List[bytes] = []
    if attestation_result is not None:
        trust_path_candidate = getattr(attestation_result, "trust_path", None)
        if trust_path_candidate:
            attestation_trust_path = list(trust_path_candidate)
    if not attestation_trust_path and isinstance(attestation_object.att_stmt, Mapping):
        attestation_trust_path = _collect_trust_path_entries(
            attestation_object.att_stmt.get("x5c")
        )
    return attestation_trust_path


def _evaluate_root_validation(
    results: Dict[str, Any],
    *,
    algorithm: Optional[int],
    attestation_object: Any,
    attestation_result: Any,
    client_data_hash: bytes,
    credential_aaguid_bytes: bytes,
    signature_valid: Optional[bool],
    attestation_format_value: str,
) -> Dict[str, Any]:
    attestation_trust_path = _collect_attestation_trust_path(
        attestation_result,
        attestation_object,
    )

    certificate_aaguid_bytes = b""
    if attestation_trust_path:
        certificate_aaguid_bytes = _extract_certificate_aaguid(attestation_trust_path[0])

    metadata_entry = None
    metadata_lookup_source: Optional[str] = None
    now = datetime.now(timezone.utc)
    root_valid: Optional[bool] = None
    verifier = None
    root_check_details: Optional[Dict[str, Optional[bool]]] = None

    pqc_registration = isinstance(algorithm, int) and is_pqc_algorithm(algorithm)
    if pqc_registration:
        verifier = get_mds_verifier()
        pqc_outcome = _evaluate_mldsa_attestation_root(
            attestation_object,
            credential_aaguid_bytes,
            verifier,
            now,
        )
        root_valid = pqc_outcome.get("root_valid")
        metadata_entry = pqc_outcome.get("metadata_entry") or metadata_entry
        metadata_lookup_source = pqc_outcome.get("metadata_lookup_source")
        root_check_details = pqc_outcome.get("checks")
        pqc_errors = pqc_outcome.get("errors") or []
        pqc_warnings = pqc_outcome.get("warnings") or []
        if pqc_errors:
            results["errors"].extend(str(err) for err in pqc_errors)
        if pqc_warnings:
            results["warnings"].extend(str(warn) for warn in pqc_warnings)
    elif signature_valid and attestation_result is not None:
        verifier = get_mds_verifier()
        classical_outcome = _evaluate_classical_attestation_root(
            attestation_object,
            attestation_result,
            client_data_hash,
            verifier,
            now,
        )
        root_valid = classical_outcome.get("root_valid")
        if classical_outcome.get("metadata_entry") is not None:
            metadata_entry = classical_outcome.get("metadata_entry")
            metadata_lookup_source = classical_outcome.get("metadata_lookup_source")
        elif classical_outcome.get("metadata_lookup_source"):
            metadata_lookup_source = classical_outcome.get("metadata_lookup_source")
        root_check_details = classical_outcome.get("checks")
        class_errors = classical_outcome.get("errors") or []
        class_warnings = classical_outcome.get("warnings") or []
        if class_errors:
            results["errors"].extend(str(err) for err in class_errors)
        if class_warnings:
            results["warnings"].extend(str(warn) for warn in class_warnings)
    elif signature_valid is False and attestation_format_value != "none":
        results["errors"].append("attestation_signature_invalid")
        root_valid = False

    return {
        "root_valid": root_valid,
        "metadata_entry": metadata_entry,
        "metadata_lookup_source": metadata_lookup_source,
        "root_check_details": root_check_details,
        "verifier": verifier,
        "certificate_aaguid_bytes": certificate_aaguid_bytes,
    }
