from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from cryptography import x509

from fido2.attestation import AttestationResult, AttestationType, InvalidSignature
from fido2.attestation.base import _verify_mldsa_certificate_signature
from fido2.cose import CoseKey, extract_certificate_public_key_info

from ..webauthn import metadata
from ..webauthn.pqc import PQC_ALGORITHM_ID_TO_NAME, is_pqc_algorithm
from . import trust

_PQC_ALGORITHM_NAME_TO_ID = {
    name.lower(): alg_id for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items()
}


def _normalise_pqc_algorithm_identifier(value: Any) -> int | None:
    """Return the COSE identifier for a PQC algorithm when discernible."""

    if isinstance(value, int) and is_pqc_algorithm(value):
        return value

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None

        try:
            parsed = int(stripped, 10)
        except ValueError:
            parsed = None

        if parsed is not None and is_pqc_algorithm(parsed):
            return parsed

        lowered = stripped.lower()
        mapped = _PQC_ALGORITHM_NAME_TO_ID.get(lowered)
        if mapped is not None:
            return mapped

        for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items():
            if isinstance(name, str) and name.lower() in lowered:
                return alg_id

        match = re.search(r"-?\d+", stripped)
        if match is not None:
            try:
                candidate = int(match.group(), 10)
            except ValueError:
                candidate = None
            if candidate is not None and is_pqc_algorithm(candidate):
                return candidate

    return None


def _check_pqc_certificate_constraints(
    cert_der: bytes,
    *,
    now: datetime,
    is_leaf: bool,
    remaining_subordinates: int,
) -> str | None:
    """Validate expiry, key usage and policy constraints for PQC certificates."""

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        return f"pqc_certificate_parse_error: {exc}"

    subject = trust._describe_certificate_subject(cert)
    not_before = trust._certificate_datetime(cert, "not_valid_before")
    not_after = trust._certificate_datetime(cert, "not_valid_after")
    if now < not_before or now > not_after:
        return f"pqc_certificate_out_of_validity: {subject}"

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        basic_constraints = None

    if basic_constraints is not None:
        if is_leaf and basic_constraints.ca:
            return f"pqc_basic_constraints_leaf_ca: {subject}"
        if not is_leaf and not basic_constraints.ca:
            return f"pqc_basic_constraints_not_ca: {subject}"
        if (
            not is_leaf
            and basic_constraints.ca
            and basic_constraints.path_length is not None
            and basic_constraints.path_length < remaining_subordinates
        ):
            return f"pqc_basic_constraints_path_length: {subject}"
    elif not is_leaf:
        return f"pqc_basic_constraints_missing: {subject}"

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None

    if key_usage is not None:
        if is_leaf and not (
            key_usage.digital_signature or key_usage.content_commitment
        ):
            return f"pqc_key_usage_leaf_invalid: {subject}"
        if not is_leaf and not key_usage.key_cert_sign:
            return f"pqc_key_usage_ca_invalid: {subject}"

    try:
        policy_constraints = cert.extensions.get_extension_for_class(
            x509.PolicyConstraints
        ).value
    except x509.ExtensionNotFound:
        policy_constraints = None

    if policy_constraints is not None:
        if (
            policy_constraints.require_explicit_policy is not None
            and policy_constraints.require_explicit_policy < 0
        ) or (
            policy_constraints.inhibit_policy_mapping is not None
            and policy_constraints.inhibit_policy_mapping < 0
        ):
            return f"pqc_policy_constraints_invalid: {subject}"

    return None


def _verify_pqc_attestation_chain(
    trust_path: Sequence[bytes],
    root: bytes,
    *,
    now: datetime,
) -> tuple[bool, list[str]]:
    """Verify a PQC attestation chain against *root* including constraints."""

    errors: list[str] = []
    if not trust_path:
        return False, ["pqc_attestation_chain_missing"]

    candidate_chain = list(trust_path)
    if not candidate_chain or candidate_chain[-1] != root:
        candidate_chain.append(root)

    for idx, cert_der in enumerate(candidate_chain):
        is_leaf = idx == 0
        remaining_subordinates = len(candidate_chain) - idx - 1
        constraint_error = _check_pqc_certificate_constraints(
            cert_der,
            now=now,
            is_leaf=is_leaf,
            remaining_subordinates=remaining_subordinates,
        )
        if constraint_error is not None:
            errors.append(constraint_error)
            return False, errors

        if remaining_subordinates <= 0:
            continue

        issuer_der = candidate_chain[idx + 1]
        try:
            _verify_mldsa_certificate_signature(cert_der, issuer_der)
        except InvalidSignature as exc:
            errors.append(f"pqc_certificate_signature_invalid: {exc}")
            return False, errors
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"pqc_certificate_signature_error: {exc}")
            return False, errors

    if not trust._is_trusted_ca_certificate(candidate_chain[-1], allow_subject_parsing=False):
        errors.append("pqc_root_not_in_trusted_list")
        return False, errors

    return True, errors


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

    metadata_entry = trust._find_metadata_entry_for_aaguid(verifier, aaguid_bytes)
    if metadata_entry is None:
        checks["trusted_ca"] = False
        errors.append("pqc_metadata_entry_missing")
        return {
            "root_valid": trust._resolve_root_validity(checks),
            "metadata_entry": None,
            "metadata_lookup_source": None,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    metadata_lookup_source = "aaguid"

    roots = trust._collect_metadata_root_certificates(metadata_entry)
    if not roots:
        errors.append("pqc_metadata_root_missing")
        checks["trusted_ca"] = False
        return {
            "root_valid": trust._resolve_root_validity(checks),
            "metadata_entry": metadata_entry,
            "metadata_lookup_source": metadata_lookup_source,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    trusted_roots = [
        root
        for root in roots
        if trust._is_trusted_ca_certificate(root, allow_subject_parsing=False)
    ]
    if not trusted_roots:
        errors.append("attestation_root_not_trusted")
        checks["trusted_ca"] = False
        return {
            "root_valid": trust._resolve_root_validity(checks),
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
        trust_path = trust._collect_trust_path_entries(att_stmt.get("x5c"))

    if not trust_path:
        checks["chain"] = False
        errors.append("pqc_attestation_chain_missing")
    else:
        chain_valid = False
        chain_errors: list[str] = []
        for root in trusted_roots:
            valid, attempt_errors = _verify_pqc_attestation_chain(
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
        "root_valid": trust._resolve_root_validity(checks),
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

    algorithm = _normalise_pqc_algorithm_identifier(statement.get("alg"))
    if algorithm is None or not is_pqc_algorithm(algorithm):
        return outcome

    signature = trust._coerce_bytes(statement.get("sig"))
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

    trust_path = trust._collect_trust_path_entries(statement.get("x5c"))
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

        public_key_bytes = trust._coerce_bytes(info.get("subject_public_key"))
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
