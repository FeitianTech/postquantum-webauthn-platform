"""The codes the attestation checks report, and the ones that refuse a Simple registration.

An error or warning is a code (``trust_path_missing``), or a code and the
message of the exception behind it, after ": " (``cose_key_error: …``). An
exception without a message gives the bare code, so no finding is empty and
none ends in ": ".
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.attestation import InvalidData, InvalidSignature, UnsupportedType

# The errors that say the ceremony itself did not hold: the response is not the
# one the request asked for, or its attestation statement does not verify. The
# Simple tab refuses a registration on these alone. Every other error says what
# the attestation proves about the authenticator (its chain, its root, its
# metadata), which a relying party that asked for no attestation does not hold
# against the registration.
INTEGRITY_ERRORS = frozenset(
    {
        "registration_response_invalid",
        "registration_parse_error",
        "client_data_type_invalid",
        "challenge_mismatch",
        "origin_mismatch",
        "cross_origin_not_allowed",
        "rp_id_hash_mismatch",
        "user_presence_missing",
        "user_verification_required_not_satisfied",
        "attested_credential_data_missing",
        "algorithm_not_allowed",
        "cose_key_error",
        "unsupported_attestation",
        "attestation_invalid",
        "attestation_error",
        "attestation_signature_invalid",
    }
)


def with_reason(code: str, exc: BaseException) -> str:
    """``code``, followed by ``exc``'s message when it has one."""

    return f"{code}: {exc}" if str(exc).strip() else code


def statement_error(exc: Exception) -> str:
    """The code of an attestation statement fido2 refused: a format it does not read, a statement that does not verify, or another failure."""

    if isinstance(exc, UnsupportedType):
        return with_reason("unsupported_attestation", exc)
    if isinstance(exc, (InvalidSignature, InvalidData)):
        return with_reason("attestation_invalid", exc)
    return with_reason("attestation_error", exc)


def chain_error(exc: Exception) -> str:
    """The code of a certificate chain that did not verify: one certificate not issued by the next, or one that does not read."""

    if isinstance(exc, InvalidSignature):
        return "certificate_chain_invalid"
    return with_reason("certificate_chain_unreadable", exc)


def error_code(finding: str) -> str:
    """A finding's code: the text before its reason."""

    return finding.split(":", 1)[0]


def integrity_errors_only(results: Mapping[str, Any]) -> dict[str, Any]:
    """``results`` with only its integrity errors left as errors; every other one follows its warnings, in order."""

    errors = results.get("errors")
    if not isinstance(errors, list):
        return dict(results)
    warnings = results.get("warnings")
    kept = [error for error in errors if error_code(str(error)) in INTEGRITY_ERRORS]
    moved = [error for error in errors if error_code(str(error)) not in INTEGRITY_ERRORS]
    return {**results, "errors": kept, "warnings": [*(warnings if isinstance(warnings, list) else []), *moved]}
