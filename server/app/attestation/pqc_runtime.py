from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from fido2.attestation import AttestationResult, AttestationType
from fido2.cose import CoseKey, extract_certificate_public_key_info

from .. import metadata
from ..pqc import is_pqc_algorithm
from . import pqc_constraints_runtime, trust_ca_runtime, trust_runtime


def _evaluate_mldsa_attestation_root(
    attestation_object: Any,
    aaguid_bytes: bytes,
    verifier: Any | None,
    now: datetime,
) -> dict[str, Any]:
    """Determine ML-DSA attestation root status using PQC-only verification."""

    warnings: list[str] = []
    errors: list[str] = []
    metadata_entry: Any | None = None
    metadata_lookup_source: str | None = None
    checks: dict[str, bool | None] = {
        "trusted_ca": None,
        "chain": None,
        "fido_mds": None,
    }

    if verifier is None:
        warnings.append("metadata_not_available")
        return {
            "root_valid": None,
            "metadata_entry": None,
            "metadata_lookup_source": None,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    metadata_entry = trust_runtime._find_metadata_entry_for_aaguid(verifier, aaguid_bytes)
    if metadata_entry is None:
        checks["trusted_ca"] = False
        errors.append("pqc_metadata_entry_missing")
        return {
            "root_valid": trust_runtime._resolve_root_validity(checks),
            "metadata_entry": None,
            "metadata_lookup_source": None,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    metadata_lookup_source = "aaguid"

    roots = trust_runtime._collect_metadata_root_certificates(metadata_entry)
    if not roots:
        errors.append("pqc_metadata_root_missing")
        checks["trusted_ca"] = False
        return {
            "root_valid": trust_runtime._resolve_root_validity(checks),
            "metadata_entry": metadata_entry,
            "metadata_lookup_source": metadata_lookup_source,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    trusted_roots = [
        root
        for root in roots
        if trust_ca_runtime._is_trusted_ca_certificate(root, allow_subject_parsing=False)
    ]
    if not trusted_roots:
        errors.append("attestation_root_not_trusted")
        checks["trusted_ca"] = False
        return {
            "root_valid": trust_runtime._resolve_root_validity(checks),
            "metadata_entry": metadata_entry,
            "metadata_lookup_source": metadata_lookup_source,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    checks["trusted_ca"] = True

    fido_status = metadata.metadata_entry_trust_anchor_status(metadata_entry)
    if fido_status is True:
        checks["fido_mds"] = True
    elif fido_status is False:
        checks["fido_mds"] = False
        errors.append("pqc_metadata_not_fido_trusted")

    att_stmt = getattr(attestation_object, "att_stmt", None)
    trust_path: Sequence[bytes] = []
    if isinstance(att_stmt, Mapping):
        trust_path = trust_runtime._collect_trust_path_entries(att_stmt.get("x5c"))

    if not trust_path:
        checks["chain"] = False
        errors.append("pqc_attestation_chain_missing")
    else:
        chain_valid = False
        chain_errors: list[str] = []
        for root in trusted_roots:
            valid, attempt_errors = pqc_constraints_runtime._verify_pqc_attestation_chain(
                trust_path,
                root,
                now=now,
            )
            if valid:
                chain_valid = True
                chain_errors = []
                break
            chain_errors.extend(attempt_errors)

        checks["chain"] = chain_valid
        if not chain_valid:
            for err in chain_errors or ["pqc_root_verification_failed"]:
                if err not in errors:
                    errors.append(err)

    return {
        "root_valid": trust_runtime._resolve_root_validity(checks),
        "metadata_entry": metadata_entry,
        "metadata_lookup_source": metadata_lookup_source,
        "warnings": warnings,
        "errors": errors,
        "checks": checks,
    }


def _attempt_pqc_attestation_signature_validation(
    attestation_object: Any, client_data_hash: bytes
) -> dict[str, Any]:
    """Best-effort PQC attestation verification fallback using cryptography."""

    outcome: dict[str, Any] = {
        "attempted": False,
        "success": False,
        "attestation_result": None,
        "error": None,
    }

    statement = getattr(attestation_object, "att_stmt", None)
    if not isinstance(statement, Mapping):
        return outcome

    algorithm = pqc_constraints_runtime._normalise_pqc_algorithm_identifier(statement.get("alg"))
    if algorithm is None or not is_pqc_algorithm(algorithm):
        return outcome

    signature = trust_runtime._coerce_bytes(statement.get("sig"))
    if not signature:
        outcome["attempted"] = True
        outcome["error"] = "pqc_attestation_missing_signature"
        return outcome

    try:
        cose_cls = CoseKey.for_alg(algorithm)
    except Exception as exc:  # pragma: no cover - defensive guard
        outcome["attempted"] = True
        outcome["error"] = f"pqc_attestation_unsupported_algorithm: {exc}"
        return outcome

    trust_path = trust_runtime._collect_trust_path_entries(statement.get("x5c"))
    attestation_type = AttestationType.SELF

    if trust_path:
        attestation_type = AttestationType.BASIC
        cert_bytes = trust_path[0]
        try:
            info = extract_certificate_public_key_info(cert_bytes)
        except Exception as exc:
            outcome["attempted"] = True
            outcome["error"] = f"pqc_attestation_public_key_error: {exc}"
            return outcome

        public_key_bytes = trust_runtime._coerce_bytes(info.get("subject_public_key"))
        if public_key_bytes is None:
            outcome["attempted"] = True
            outcome["error"] = "pqc_attestation_public_key_missing"
            return outcome

        try:
            public_key = cose_cls({1: 7, 3: algorithm, -1: public_key_bytes})
        except Exception as exc:
            outcome["attempted"] = True
            outcome["error"] = f"pqc_attestation_public_key_invalid: {exc}"
            return outcome
    else:
        credential_data = getattr(attestation_object.auth_data, "credential_data", None)
        if credential_data is None:
            outcome["attempted"] = True
            outcome["error"] = "pqc_attestation_credential_data_missing"
            return outcome

        try:
            public_key = CoseKey.parse(credential_data.public_key)
        except Exception as exc:
            outcome["attempted"] = True
            outcome["error"] = f"pqc_attestation_public_key_parse_error: {exc}"
            return outcome

        if getattr(public_key, "ALGORITHM", None) != algorithm:
            outcome["attempted"] = True
            outcome["error"] = "pqc_attestation_algorithm_mismatch"
            return outcome

    message = bytes(attestation_object.auth_data) + client_data_hash

    outcome["attempted"] = True
    try:
        public_key.verify(message, signature)
    except Exception as exc:
        outcome["error"] = f"pqc_attestation_verification_failed: {exc}"
        return outcome

    outcome["success"] = True
    outcome["attestation_result"] = AttestationResult(attestation_type, trust_path)
    return outcome
