from __future__ import annotations

from typing import Any, Dict, List, Mapping


def initialize_registration_context_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    attestation_summary = {
        "signatureValid": ctx["attestation_signature_valid"],
        "rootValid": ctx["attestation_root_valid"],
        "rpIdHashValid": ctx["attestation_rp_id_hash_valid"],
        "aaguidMatch": ctx["attestation_aaguid_match"],
    }

    metadata_summary = ctx["attestation_checks_safe"].get("metadata")
    if isinstance(metadata_summary, Mapping):
        attestation_summary["metadata"] = metadata_summary

    warnings_summary = ctx["attestation_checks_safe"].get("warnings")
    warnings: List[str] = []
    if isinstance(warnings_summary, list):
        filtered_warnings: List[Any] = []
        for message in warnings_summary:
            if isinstance(message, str):
                stripped = message.strip()
                if stripped:
                    warnings.append(stripped)
                    filtered_warnings.append(stripped)
            elif message:
                filtered_warnings.append(message)
        if filtered_warnings:
            attestation_summary["warnings"] = filtered_warnings

    credential_info: Dict[str, Any] = {
        "credential_data": ctx["auth_data"].credential_data,
        "auth_data": ctx["auth_data"],
        "user_info": {
            "name": ctx["uname"],
            "display_name": ctx["uname"],
            "user_handle": ctx["uname"].encode("utf-8"),
        },
        "registration_time": simple_module.time.time(),
        "client_data_json": ctx["client_data_json"] or "",
        "attestation_object": ctx["raw_attestation_object"] or "",
        "attestation_object_raw": ctx["raw_attestation_object"] or "",
        "attestation_format": ctx["attestation_format"],
        "attestation_statement": ctx["attestation_statement"],
        "attestation_certificate": ctx["attestation_certificate_details"],
        "attestation_certificates": ctx["attestation_certificates_details"],
        "client_extension_outputs": ctx["client_extension_results"],
        "authenticator_attachment": ctx["authenticator_attachment_response"],
        "request_params": {
            "user_verification": "discouraged",
            "authenticator_attachment": "cross-platform",
            "attestation": "none",
            "resident_key": None,
            "extensions": {},
            "timeout": 90000,
        },
        "properties": {
            "excludeCredentialsSentCount": 0,
            "excludeCredentialsUsed": False,
            "credentialIdLength": len(ctx["auth_data"].credential_data.credential_id),
            "fakeCredentialIdLengthRequested": None,
            "hintsSent": [],
            "resolvedAuthenticatorAttachments": [],
            "authenticatorAttachment": ctx["authenticator_attachment_response"],
            "largeBlobRequested": {},
            "largeBlobClientOutput": ctx["client_extension_results"].get("largeBlob", {}),
            "residentKeyRequested": None,
            "residentKeyRequired": False,
        },
    }

    credential_properties = credential_info["properties"]
    credential_properties["attestationSignatureValid"] = ctx["attestation_signature_valid"]
    credential_properties["attestationRootValid"] = ctx["attestation_root_valid"]
    credential_properties["attestationRpIdHashValid"] = ctx["attestation_rp_id_hash_valid"]
    credential_properties["attestationAaguidMatch"] = ctx["attestation_aaguid_match"]
    credential_properties["attestationChecks"] = ctx["attestation_checks_safe"]
    credential_properties["attestationSummary"] = attestation_summary
    if warnings:
        credential_properties["attestationWarnings"] = warnings

    if ctx["min_pin_length_value"] is not None:
        credential_properties["minPinLength"] = ctx["min_pin_length_value"]

    simple_module.add_public_key_material(
        credential_info,
        getattr(ctx["auth_data"].credential_data, "public_key", {}),
    )

    if ctx["parsed_attestation_object"]:
        credential_info["attestation_object_decoded"] = simple_module.make_json_safe(
            ctx["parsed_attestation_object"]
        )

    if ctx["attestation_certificates_details"]:
        credential_info["attestationCertificates"] = ctx["attestation_certificates_details"]
        credential_properties["attestationCertificates"] = ctx["attestation_certificates_details"]

    if isinstance(ctx["response"], Mapping):
        credential_info["registration_response"] = simple_module.make_json_safe(ctx["response"])

    credential_data = ctx["auth_data"].credential_data
    aaguid_value = getattr(credential_data, "aaguid", None)
    if aaguid_value is not None:
        try:
            aaguid_bytes = bytes(aaguid_value)
        except Exception:
            aaguid_bytes = None
        if aaguid_bytes is not None and len(aaguid_bytes) == 16:
            aaguid_hex = aaguid_bytes.hex()
            credential_properties["aaguid"] = aaguid_hex
            credential_properties["aaguidHex"] = aaguid_hex
            try:
                credential_properties["aaguidGuid"] = str(simple_module.uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                pass

    ctx["metadata_summary"] = metadata_summary
    ctx["warnings"] = warnings
    ctx["attestation_summary"] = attestation_summary
    ctx["credential_info"] = credential_info
    ctx["credential_properties"] = credential_properties
