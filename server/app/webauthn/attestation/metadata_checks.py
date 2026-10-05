"""The MDS metadata a registration's authenticator has: its entry, what the entry says, and whether its AAGUID matches."""
from __future__ import annotations

from typing import Any

from fido2.webauthn import Aaguid

from ...mds import verifier as mds_verifier


def _metadata_entry_by_aaguid(verifier: Any, credential_aaguid_bytes: bytes) -> Any:
    """The metadata entry for the credential's AAGUID, or ``None``; a failed lookup is no entry."""

    try:
        aaguid_obj = Aaguid(credential_aaguid_bytes)
    except (TypeError, ValueError):
        return None
    if verifier is None:
        verifier = mds_verifier.get_mds_verifier()
    if verifier is None:
        return None
    try:
        return verifier.find_entry_by_aaguid(aaguid_obj)
    except Exception:
        return None


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
    if (
        isinstance(authenticator_info, dict)
        and isinstance(algorithm, int)
    ):
        alg_list = authenticator_info.get("algorithms")
        if isinstance(alg_list, (list, tuple)):
            numeric_algs = [alg for alg in alg_list if isinstance(alg, int)]
            if numeric_algs:
                metadata_algorithm_supported = algorithm in numeric_algs
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
    if metadata_entry is None and credential_aaguid_bytes:
        fallback_entry = _metadata_entry_by_aaguid(verifier, credential_aaguid_bytes)
        if fallback_entry is not None:
            metadata_entry = fallback_entry
            metadata_lookup_source = "aaguid"

    facts: dict[str, Any] = {
        "description": None,
        "aaguid": None,
        "algorithm_supported": None,
        "root_certificates_present": False,
    }
    if metadata_entry is not None:
        facts = _metadata_entry_facts(metadata_entry, results["authenticator_data"].get("algorithm"))

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
