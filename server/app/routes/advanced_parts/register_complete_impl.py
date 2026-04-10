from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from .register_complete_finalize_impl import finalize_registration_completion
from .register_complete_material_impl import build_registration_material
from .register_complete_setup_impl import prepare_register_complete_inputs
from .register_complete_state_impl import resolve_state_and_registration_server


def advanced_register_complete_impl(advanced_module: Any):
    data = advanced_module.request.get_json(silent=True) or {}
    prepared, error_response = prepare_register_complete_inputs(advanced_module, data)
    if error_response is not None:
        return error_response
    if prepared is None:
        return advanced_module.jsonify({"error": "Invalid request"}), 400

    response = prepared["response"]
    original_request = prepared["originalRequest"]
    public_key = prepared["publicKey"]
    user_info = prepared["userInfo"]
    username = prepared["username"]
    display_name = prepared["displayName"]
    metadata_session_id = prepared["metadataSessionId"]
    allowed_attachments = prepared["allowedAttachments"]
    resident_key_requested = prepared["residentKeyRequested"]
    resident_key_required = prepared["residentKeyRequired"]
    attestation_format = prepared["attestationFormat"]
    attestation_statement = prepared["attestationStatement"]
    attestation_certificate_details = prepared["attestationCertificateDetails"]
    attestation_certificates_details = prepared["attestationCertificatesDetails"]
    attestation_object_b64 = prepared["attestationObjectB64"]
    raw_attestation_object = prepared["rawAttestationObject"]
    client_data_json_b64 = prepared["clientDataJsonB64"]
    client_data_json = prepared["clientDataJson"]
    client_extension_results = prepared["clientExtensionResults"]
    min_pin_length_value = prepared["minPinLengthValue"]
    authenticator_attachment_response = prepared["authenticatorAttachmentResponse"]

    warnings: List[str] = []

    try:
        state_ctx, state_error = resolve_state_and_registration_server(
            advanced_module,
            data=data,
            original_request=original_request,
            public_key=public_key,
            response=response if isinstance(response, Mapping) else {},
            attestation_format=attestation_format,
            attestation_statement=attestation_statement,
            raw_attestation_object=raw_attestation_object,
        )
        if state_error is not None:
            return state_error
        if state_ctx is None:
            return advanced_module.jsonify({"error": "Registration state not found"}), 400

        state = state_ctx["state"]
        stored_original_request = state_ctx["storedOriginalRequest"]
        resolved_rp_id = state_ctx["resolvedRpId"]
        auth_data = state_ctx["authData"]

        stored_public_key: Optional[Mapping[str, Any]] = None
        if isinstance(stored_original_request, Mapping):
            stored_public_key = stored_original_request.get("publicKey")
            if not isinstance(stored_public_key, Mapping):
                stored_public_key = None

        public_key_for_checks: Optional[Mapping[str, Any]] = (
            stored_public_key if isinstance(stored_public_key, Mapping) else public_key
        )

        expected_origin = advanced_module.request.headers.get("Origin") or advanced_module.request.host_url.rstrip("/")
        attestation_checks = advanced_module.perform_attestation_checks(
            response if isinstance(response, Mapping) else {},
            state if isinstance(state, Mapping) else None,
            public_key_for_checks,
            auth_data,
            expected_origin,
            resolved_rp_id,
        )

        attestation_signature_valid = attestation_checks.get("signature_valid")
        attestation_root_valid = attestation_checks.get("root_valid")
        attestation_rp_id_hash_valid = attestation_checks.get("rp_id_hash_valid")
        attestation_aaguid_match = attestation_checks.get("aaguid_match")
        attestation_checks_safe = advanced_module.make_json_safe(attestation_checks)

        attestation_warnings = attestation_checks.get("warnings")
        if isinstance(attestation_warnings, list):
            for message in attestation_warnings:
                if isinstance(message, str):
                    stripped = message.strip()
                    if stripped:
                        warnings.append(stripped)

        attestation_summary = {
            "signatureValid": attestation_signature_valid,
            "rootValid": attestation_root_valid,
            "rpIdHashValid": attestation_rp_id_hash_valid,
            "aaguidMatch": attestation_aaguid_match,
        }
        metadata_summary = attestation_checks_safe.get("metadata")
        if isinstance(metadata_summary, Mapping):
            attestation_summary["metadata"] = metadata_summary
        warnings_summary = attestation_checks_safe.get("warnings")
        if isinstance(warnings_summary, list) and warnings_summary:
            attestation_summary["warnings"] = warnings_summary

        authenticator_extensions_summary: Dict[str, Any] = {}
        if hasattr(auth_data, "extensions"):
            authenticator_extensions = getattr(auth_data, "extensions")
            if isinstance(authenticator_extensions, Mapping):
                authenticator_extensions_summary = advanced_module.summarize_authenticator_extensions(
                    authenticator_extensions
                )

        user_id_value = user_info.get("id", "")
        if user_id_value:
            try:
                user_handle = advanced_module._extract_binary_value(user_id_value)
                if isinstance(user_handle, str):
                    user_handle = bytes.fromhex(user_handle)
            except (ValueError, TypeError):
                user_handle = username.encode("utf-8")
        else:
            user_handle = username.encode("utf-8")

        credential_info = {
            "credential_data": auth_data.credential_data,
            "auth_data": auth_data,
            "user_info": {
                "name": username,
                "display_name": display_name,
                "user_handle": user_handle,
            },
            "registration_time": advanced_module.time.time(),
            "client_data_json": client_data_json or "",
            "attestation_object": raw_attestation_object or "",
            "attestation_format": attestation_format,
            "attestation_statement": attestation_statement,
            "attestation_certificates": attestation_certificates_details,
            "client_extension_outputs": client_extension_results,
            "authenticator_attachment": authenticator_attachment_response,
            "original_webauthn_request": original_request,
            "properties": {
                "excludeCredentialsSentCount": len(public_key.get("excludeCredentials", [])),
                "excludeCredentialsUsed": False,
                "credentialIdLength": len(auth_data.credential_data.credential_id),
                "fakeCredentialIdLengthRequested": None,
                "hintsSent": public_key.get("hints", []),
                "resolvedAuthenticatorAttachments": allowed_attachments,
                "authenticatorAttachment": authenticator_attachment_response,
                "largeBlobRequested": public_key.get("extensions", {}).get("largeBlob", {}),
                "largeBlobClientOutput": client_extension_results.get("largeBlob", {}),
                "residentKeyRequested": resident_key_requested,
                "residentKeyRequired": bool(resident_key_required),
                "attestationSignatureValid": attestation_signature_valid,
                "attestationRootValid": attestation_root_valid,
                "attestationRpIdHashValid": attestation_rp_id_hash_valid,
                "attestationAaguidMatch": attestation_aaguid_match,
                "attestationChecks": attestation_checks_safe,
                "attestationSummary": attestation_summary,
            },
        }

        if min_pin_length_value is not None:
            credential_info["properties"]["minPinLength"] = min_pin_length_value
        if attestation_certificates_details:
            credential_info["attestationCertificates"] = attestation_certificates_details
            credential_info["properties"]["attestationCertificates"] = attestation_certificates_details

        advanced_module.add_public_key_material(credential_info, getattr(auth_data.credential_data, "public_key", {}))
        advanced_module.augment_aaguid_fields(credential_info)
        if authenticator_extensions_summary:
            credential_info["authenticator_extensions"] = authenticator_extensions_summary
        if attestation_certificate_details is not None:
            credential_info["attestation_certificate"] = attestation_certificate_details
        if isinstance(response, Mapping):
            credential_info["registration_response"] = advanced_module.make_json_safe(response)

        credential_public_key_value = getattr(auth_data.credential_data, "public_key", None)
        raw_alg_value: Any = None
        if isinstance(credential_public_key_value, Mapping):
            if 3 in credential_public_key_value:
                raw_alg_value = credential_public_key_value[3]
            elif "alg" in credential_public_key_value:
                raw_alg_value = credential_public_key_value["alg"]
        else:
            try:
                raw_alg_value = credential_public_key_value[3]  # type: ignore[index]
            except Exception:
                raw_alg_value = None

        algo = advanced_module._coerce_cose_algorithm(raw_alg_value)
        credential_info["publicKeyAlgorithm"] = algo
        algoname = advanced_module.describe_algorithm(algo)
        advanced_module.log_algorithm_selection("registration", algo)

        pub_key_params = public_key.get("pubKeyCredParams", [])
        algorithms_used = [param.get("alg") for param in pub_key_params if isinstance(param, dict) and "alg" in param]
        debug_info = {
            "attestationFormat": attestation_format,
            "algorithmsUsed": algorithms_used or ([algo] if algo is not None else []),
            "excludeCredentialsUsed": bool(public_key.get("excludeCredentials")),
            "hintsUsed": public_key.get("hints", []),
            "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, "flags") else False,
            "attestationSignatureValid": attestation_signature_valid,
            "attestationRootValid": attestation_root_valid,
            "attestationRpIdHashValid": attestation_rp_id_hash_valid,
            "attestationAaguidMatch": attestation_aaguid_match,
            "attestationChecks": attestation_checks_safe,
            "attestationSummary": attestation_summary,
        }

        extensions_requested = public_key.get("extensions", {})
        if not isinstance(extensions_requested, dict):
            extensions_requested = {}
        cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
        if cred_protect_requested is None:
            cred_protect_requested = extensions_requested.get("credProtect")
        if isinstance(cred_protect_requested, int):
            debug_info["credProtectUsed"] = {
                1: "userVerificationOptional",
                2: "userVerificationOptionalWithCredentialIDList",
                3: "userVerificationRequired",
            }.get(cred_protect_requested, cred_protect_requested)
        elif cred_protect_requested:
            debug_info["credProtectUsed"] = cred_protect_requested
        else:
            debug_info["credProtectUsed"] = "none"

        enforce_requested = extensions_requested.get("enforceCredentialProtectionPolicy")
        if enforce_requested is None:
            enforce_requested = extensions_requested.get("enforceCredProtect")
        debug_info["enforceCredProtectUsed"] = bool(enforce_requested)

        material = build_registration_material(
            advanced_module,
            auth_data=auth_data,
            attestation_format=attestation_format,
            attestation_statement=attestation_statement,
            attestation_certificate_details=attestation_certificate_details,
            attestation_certificates_details=attestation_certificates_details,
            client_extension_results=client_extension_results,
            credential_info=credential_info,
            response=response,
            user_handle=user_handle,
            resolved_rp_id=resolved_rp_id,
            resident_key_required=bool(resident_key_required),
            attestation_rp_id_hash_valid=attestation_rp_id_hash_valid,
            attestation_checks_safe=attestation_checks_safe,
            attestation_summary=attestation_summary,
        )

        if authenticator_extensions_summary:
            material["rpInfo"]["registrationData"]["authenticatorExtensions"] = advanced_module.make_json_safe(
                authenticator_extensions_summary
            )

        return finalize_registration_completion(
            advanced_module,
            stored_credential=material["storedCredential"],
            rp_info=material["rpInfo"],
            metadata_summary=metadata_summary,
            response=response,
            metadata_session_id=metadata_session_id,
            username=username,
            warnings=warnings,
            debug_info=debug_info,
            algoname=algoname,
            resolved_rp_id=resolved_rp_id,
            credential_id_bytes=material["credentialIdBytes"],
            aaguid_bytes=material.get("aaguidBytes"),
            auth_data=auth_data,
            attestation_format=attestation_format,
            attestation_object_b64=attestation_object_b64,
            client_data_json_b64=client_data_json_b64,
            user_handle=user_handle,
            display_name=display_name,
        )
    except Exception as exc:
        return advanced_module.jsonify({"error": str(exc)}), 400
