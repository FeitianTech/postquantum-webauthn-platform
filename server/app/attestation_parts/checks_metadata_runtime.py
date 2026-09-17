from __future__ import annotations

from typing import Any

from fido2.webauthn import Aaguid

from .. import metadata


def _finalize_metadata_results(
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
    metadata_description: str | None = None
    metadata_aaguid: str | None = None
    metadata_algorithm_supported: bool | None = None
    metadata_aaguid_bytes = b""
    metadata_root_certificates_present = False
    metadata_verification_warning: str | None = None

    if metadata_entry is None and credential_aaguid_bytes:
        try:
            aaguid_obj = Aaguid.fromhex(credential_aaguid_bytes.hex())
        except Exception:
            aaguid_obj = None
        if aaguid_obj is not None:
            if verifier is None:
                verifier = metadata.get_mds_verifier()
            if verifier is not None:
                try:
                    fallback_entry = verifier.find_entry_by_aaguid(aaguid_obj)
                except Exception:
                    None
                else:
                    if fallback_entry is not None:
                        metadata_entry = fallback_entry
                        metadata_lookup_source = "aaguid"

    if metadata_entry is not None:
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
        algorithm = results["authenticator_data"].get("algorithm")
        if (
            isinstance(authenticator_info, dict)
            and isinstance(algorithm, int)
        ):
            alg_list = authenticator_info.get("algorithms")
            if isinstance(alg_list, (list, tuple)):
                numeric_algs = [alg for alg in alg_list if isinstance(alg, int)]
                if numeric_algs:
                    metadata_algorithm_supported = algorithm in numeric_algs
        entry_aaguid = getattr(metadata_entry, "aaguid", None)
        if entry_aaguid is not None:
            try:
                metadata_aaguid = str(entry_aaguid)
                metadata_aaguid_bytes = bytes(entry_aaguid)  # noqa: F841  # FIXME: computed but never compared, unlike the credential/certificate aaguids
            except Exception:
                pass

    credential_aaguid_value = credential_aaguid_bytes if credential_aaguid_bytes else None
    certificate_aaguid_value = certificate_aaguid_bytes if certificate_aaguid_bytes else None

    if credential_aaguid_value and certificate_aaguid_value:
        results["aaguid_match"] = (
            credential_aaguid_value == certificate_aaguid_value
        )
    else:
        results["aaguid_match"] = None

    results["metadata"] = {
        "available": metadata_entry is not None,
        "description": metadata_description,
        "aaguid": metadata_aaguid,
        "algorithm_supported": metadata_algorithm_supported,
        "root_certificates_present": metadata_root_certificates_present,
    }

    if metadata_lookup_source:
        results["metadata"]["source"] = metadata_lookup_source
    if metadata_verification_warning:
        results["metadata"]["verification_warning"] = metadata_verification_warning

    # The AAGUID exposed during registration originates from the attestation
    # object. Metadata mismatches are surfaced through ``results["metadata"]``,
    # while ``results["aaguid_match"]`` only reflects whether the authenticator
    # data and attestation certificate agree.
    if metadata_algorithm_supported is False:
        results["errors"].append("algorithm_not_in_metadata")

    if root_check_details:
        results["root_checks"] = root_check_details

    if root_valid is not None:
        results["root_valid"] = root_valid
