from __future__ import annotations

import re
from datetime import datetime
from typing import Any, List, Optional, Sequence, Tuple


def _normalise_pqc_algorithm_identifier(value: Any) -> Optional[int]:
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
) -> Optional[str]:
    """Validate expiry, key usage and policy constraints for PQC certificates."""

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        return f"pqc_certificate_parse_error: {exc}"

    subject = _describe_certificate_subject(cert)
    not_before = _certificate_datetime(cert, "not_valid_before")
    not_after = _certificate_datetime(cert, "not_valid_after")
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
) -> Tuple[bool, List[str]]:
    """Verify a PQC attestation chain against *root* including constraints."""

    errors: List[str] = []
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

    if not _is_trusted_ca_certificate(candidate_chain[-1], allow_subject_parsing=False):
        errors.append("pqc_root_not_in_trusted_list")
        return False, errors

    return True, errors
