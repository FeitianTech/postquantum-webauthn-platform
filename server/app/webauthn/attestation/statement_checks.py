"""The attestation statement: its signature as fido2 verifies it, its trust path, and the root it chains to."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fido2.attestation import (
    Attestation,
    InvalidData,
    InvalidSignature,
    UnsupportedType,
)

from ...mds import verifier as mds_verifier
from . import classical, trust


def resolve_signature_validation(
    attestation_object: Any,
    client_data_hash: bytes,
) -> dict[str, Any]:
    attestation_format_value = (attestation_object.fmt or "").lower()
    attestation_result = None
    attestation_errors: list[str] = []

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

    return {
        "attestation_format_value": attestation_format_value,
        "signature_valid": signature_valid,
        "attestation_result": attestation_result,
        "attestation_errors": attestation_errors,
    }


def record_signature_result(results: dict[str, Any], signature_ctx: Mapping[str, Any]) -> None:
    for error_message in signature_ctx["attestation_errors"]:
        results["errors"].append(error_message)

    results["signature_valid"] = signature_ctx["signature_valid"]


def _collect_attestation_trust_path(
    attestation_result: Any,
    attestation_object: Any,
) -> list[bytes]:
    attestation_trust_path: list[bytes] = []
    if attestation_result is not None:
        trust_path_candidate = getattr(attestation_result, "trust_path", None)
        if trust_path_candidate:
            attestation_trust_path = list(trust_path_candidate)
    if not attestation_trust_path and isinstance(attestation_object.att_stmt, Mapping):
        attestation_trust_path = trust._collect_trust_path_entries(
            attestation_object.att_stmt.get("x5c")
        )
    return attestation_trust_path


def evaluate_root_validation(
    results: dict[str, Any],
    *,
    attestation_object: Any,
    attestation_result: Any,
    client_data_hash: bytes,
    signature_valid: bool | None,
    attestation_format_value: str,
) -> dict[str, Any]:
    attestation_trust_path = _collect_attestation_trust_path(
        attestation_result,
        attestation_object,
    )

    certificate_aaguid_bytes = b""
    if attestation_trust_path:
        certificate_aaguid_bytes = trust._extract_certificate_aaguid(attestation_trust_path[0])

    metadata_entry = None
    metadata_lookup_source: str | None = None
    now = datetime.now(timezone.utc)
    root_valid: bool | None = None
    verifier = None
    root_check_details: dict[str, bool | None] | None = None

    if signature_valid and attestation_result is not None:
        verifier = mds_verifier.get_mds_verifier()
        classical_outcome = classical._evaluate_classical_attestation_root(
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
