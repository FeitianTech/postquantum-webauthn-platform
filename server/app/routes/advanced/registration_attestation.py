"""Advanced registration complete: the ceremony origin and the attestation checks.

``check_origin_and_attestation`` refuses an origin outside the allowlist and runs
``perform_attestation_checks``; ``summarise_attestation`` turns its result into
the flags, warnings, errors and summary the response and the stored credential
report. The advanced flow reports attestation errors, it does not reject on them.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import jsonify, request

from ... import config
from ...webauthn import attestation


def check_origin_and_attestation(
    *,
    response: Any,
    state_ctx: Mapping[str, Any],
    public_key: Mapping[str, Any],
    challenge_source: Any,
) -> tuple[dict[str, Any] | None, Any]:
    """``perform_attestation_checks``' result, or the 400 for an origin outside the allowlist."""

    state = state_ctx["state"]
    stored_original_request = state_ctx["storedOriginalRequest"]

    stored_public_key: Mapping[str, Any] | None = None
    if isinstance(stored_original_request, Mapping):
        stored_public_key = stored_original_request.get("publicKey")
        if not isinstance(stored_public_key, Mapping):
            stored_public_key = None

    public_key_for_checks: Mapping[str, Any] | None = (
        stored_public_key if isinstance(stored_public_key, Mapping) else public_key
    )

    # The origin the ceremony claims, read from clientDataJSON -- NOT from
    # the request's own Origin header, which the caller also controls.
    ceremony_origin = config.extract_client_data_origin(
        response.get("response") if isinstance(response, Mapping) else None
    )
    if not config.is_origin_allowed(ceremony_origin):
        return None, (
            jsonify(
                {
                    "error": (
                        "Ceremony origin is not permitted by the configured "
                        "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                    ),
                    "challengeSource": challenge_source,
                }
            ),
            400,
        )

    expected_origin = config.determine_expected_origin(ceremony_origin) or (
        request.host_url.rstrip("/")
    )
    attestation_checks = attestation.perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_for_checks,
        state_ctx["authData"],
        expected_origin,
        state_ctx["resolvedRpId"],
    )
    return attestation_checks, None


def summarise_attestation(attestation_checks: Mapping[str, Any]) -> dict[str, Any]:
    """The flags, JSON-safe checks, warnings, errors and summary of an attestation check."""

    signature_valid = attestation_checks.get("signature_valid")
    root_valid = attestation_checks.get("root_valid")
    rp_id_hash_valid = attestation_checks.get("rp_id_hash_valid")
    aaguid_match = attestation_checks.get("aaguid_match")
    checks_safe = attestation.make_json_safe(attestation_checks)

    warnings: list[str] = []
    attestation_warnings = attestation_checks.get("warnings")
    if isinstance(attestation_warnings, list):
        for message in attestation_warnings:
            if isinstance(message, str):
                stripped = message.strip()
                if stripped:
                    warnings.append(stripped)

    errors: list[str] = []
    raw_attestation_errors = attestation_checks.get("errors")
    if isinstance(raw_attestation_errors, list):
        errors = [
            str(message) for message in raw_attestation_errors if str(message).strip()
        ]

    summary = {
        "signatureValid": signature_valid,
        "rootValid": root_valid,
        "rpIdHashValid": rp_id_hash_valid,
        "aaguidMatch": aaguid_match,
        "errors": errors,
        "verified": not errors,
    }
    pqc_signature_valid = attestation_checks.get("pqc_signature_valid")
    if pqc_signature_valid is not None:
        summary["pqcSignatureValid"] = pqc_signature_valid
    metadata_summary = checks_safe.get("metadata")
    if isinstance(metadata_summary, Mapping):
        summary["metadata"] = metadata_summary
    warnings_summary = checks_safe.get("warnings")
    if isinstance(warnings_summary, list) and warnings_summary:
        summary["warnings"] = warnings_summary

    return {
        "signatureValid": signature_valid,
        "rootValid": root_valid,
        "rpIdHashValid": rp_id_hash_valid,
        "aaguidMatch": aaguid_match,
        "checksSafe": checks_safe,
        "warnings": warnings,
        "errors": errors,
        "summary": summary,
        "metadataSummary": metadata_summary,
    }


def authenticator_extensions_summary(auth_data: Any) -> dict[str, Any]:
    """The authenticator extension outputs in authData, summarised; empty when there are none."""

    if hasattr(auth_data, "extensions"):
        authenticator_extensions = getattr(auth_data, "extensions")
        if isinstance(authenticator_extensions, Mapping):
            return attestation.summarize_authenticator_extensions(authenticator_extensions)
    return {}
