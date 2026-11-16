"""The MDS metadata a registration's authenticator has: its entry, what the entry says, and whether its AAGUID matches."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.webauthn import Aaguid

from ... import json_values
from ...mds import statement_fields
from ...mds import verifier as mds_verifier
from . import error_codes


def _metadata_entry_by_aaguid(verifier: Any, credential_aaguid_bytes: bytes) -> tuple[Any, Any]:
    """The metadata entry for the credential's AAGUID and, when it has none, the revoked
    entry it has (which the app's verifier finds apart); a failed lookup is neither."""

    try:
        aaguid_obj = Aaguid(credential_aaguid_bytes)
    except (TypeError, ValueError):
        return None, None
    if verifier is None:
        verifier = mds_verifier.get_mds_verifier()
    if verifier is None:
        return None, None
    try:
        entry = verifier.find_entry_by_aaguid(aaguid_obj)
        if entry is None and isinstance(verifier, mds_verifier.IndexedVerifier):
            return None, verifier.find_revoked_entry_by_aaguid(aaguid_obj)
        return entry, None
    except Exception:
        return None, None


def _report_revoked(errors: list[str]) -> None:
    """An authenticator whose only entry is revoked is reported as revoked, not as having none."""

    if "metadata_entry_missing" in errors:
        errors.remove("metadata_entry_missing")
    errors.append("metadata_entry_revoked")


def _listed_algorithms(algorithms: Any) -> list[int]:
    """The COSE algorithms an entry's getInfo lists: MDS writes each as ``{"type": "public-key", "alg": -7}``; a bare number is read too."""

    if not isinstance(algorithms, (list, tuple)):
        return []
    listed: list[int] = []
    for listed_algorithm in algorithms:
        alg = listed_algorithm.get("alg") if isinstance(listed_algorithm, Mapping) else listed_algorithm
        if isinstance(alg, int):
            listed.append(alg)
    return listed


def _metadata_entry_facts(metadata_entry: Any, algorithm: Any) -> dict[str, Any]:
    """What an entry says: its description, root certificates, algorithms and AAGUID."""

    metadata_description: str | None = None
    metadata_aaguid: str | None = None
    metadata_algorithm_supported: bool | None = None
    metadata_root_certificates_present = False

    metadata_statement = getattr(metadata_entry, "metadata_statement", None)
    if getattr(metadata_statement, "description", None):
        metadata_description = metadata_statement.description
    authenticator_info = getattr(
        metadata_statement,
        "authenticator_get_info",
        None,
    )
    root_certs = getattr(
        metadata_statement,
        "attestation_root_certificates",
        None,
    )
    if not root_certs and isinstance(metadata_statement, dict):
        root_certs = metadata_statement.get("attestation_root_certificates") or metadata_statement.get(
            "attestationRootCertificates"
        )
    if isinstance(root_certs, (list, tuple, set)):
        metadata_root_certificates_present = any(bool(cert) for cert in root_certs)
    elif root_certs:
        metadata_root_certificates_present = True
    if isinstance(authenticator_info, dict) and isinstance(algorithm, int):
        listed_algorithms = _listed_algorithms(authenticator_info.get("algorithms"))
        if listed_algorithms:
            metadata_algorithm_supported = algorithm in listed_algorithms
    # Reported, not compared with the credential's AAGUID: every entry here
    # was looked up by that AAGUID (fido2's ca_lookup whenever there is one,
    # the PQC path and the fallback above), so they cannot differ. The one
    # other lookup, by certificate chain, runs only for a credential with no
    # AAGUID -- fido-u2f's is zero by definition -- where they always would.
    entry_aaguid = getattr(metadata_entry, "aaguid", None)
    if entry_aaguid is not None:
        # A fido2 Aaguid: its text is its hex, dashed.
        metadata_aaguid = str(entry_aaguid)

    return {
        "description": metadata_description,
        "aaguid": metadata_aaguid,
        "algorithm_supported": metadata_algorithm_supported,
        "root_certificates_present": metadata_root_certificates_present,
    }


def _status_reports(metadata_entry: Any) -> list[Any]:
    """An entry's status reports as JSON, which the MDS explorer's readers take."""

    return json_values.make_json_safe(list(getattr(metadata_entry, "status_reports", None) or []))


def _status_facts(reports: list[Any]) -> dict[str, str | None]:
    """What status reports say, as the MDS explorer reads them: the latest status and
    the highest certification, each None without one."""

    return {
        "latest_status": statement_fields.latest_status(reports) or None,
        "certification_level": statement_fields.certification_level(reports) or None,
    }


def finalize_metadata_results(
    results: dict[str, Any],
    *,
    metadata_entry: Any,
    metadata_lookup_source: str | None,
    verifier: Any,
    credential_aaguid_bytes: bytes,
    certificate_aaguid_bytes: bytes,
    root_check_details: dict[str, bool | None] | None,
    root_valid: bool | None,
) -> None:
    revoked_entry = None
    if metadata_entry is None and credential_aaguid_bytes:
        fallback_entry, revoked_entry = _metadata_entry_by_aaguid(verifier, credential_aaguid_bytes)
        if fallback_entry is not None:
            metadata_entry = fallback_entry
            metadata_lookup_source = "aaguid"

    facts: dict[str, Any] = {
        "description": None,
        "aaguid": None,
        "algorithm_supported": None,
        "root_certificates_present": False,
        "latest_status": None,
        "certification_level": None,
    }
    if metadata_entry is not None:
        reports = _status_reports(metadata_entry)
        facts = {
            **_metadata_entry_facts(metadata_entry, results["authenticator_data"].get("algorithm")),
            **_status_facts(reports),
        }
        latest = statement_fields.latest_status_code(reports)
        if latest in error_codes.UNSAFE_STATUSES:
            results["errors"].append(error_codes.unsafe_status(latest))
    elif revoked_entry is not None:
        # No entry vouches for the authenticator; its revoked one says why, and what it was.
        facts.update(_status_facts(_status_reports(revoked_entry)))
        _report_revoked(results["errors"])

    credential_aaguid_value = credential_aaguid_bytes if credential_aaguid_bytes else None
    certificate_aaguid_value = certificate_aaguid_bytes if certificate_aaguid_bytes else None

    if credential_aaguid_value and certificate_aaguid_value:
        results["aaguid_match"] = (
            credential_aaguid_value == certificate_aaguid_value
        )
    else:
        results["aaguid_match"] = None

    results["metadata"] = {"available": metadata_entry is not None, **facts}

    if metadata_lookup_source:
        results["metadata"]["source"] = metadata_lookup_source

    # The AAGUID exposed during registration originates from the attestation
    # object. Metadata mismatches are surfaced through ``results["metadata"]``,
    # while ``results["aaguid_match"]`` only reflects whether the authenticator
    # data and attestation certificate agree.
    if facts["algorithm_supported"] is False:
        results["errors"].append("algorithm_not_in_metadata")

    if root_check_details:
        results["root_checks"] = root_check_details

    if root_valid is not None:
        results["root_valid"] = root_valid
