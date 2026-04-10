from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional


def build_stored_credential_context_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    stored_credential: Dict[str, Any] = {
        "type": "simple",
        "email": ctx["uname"],
        "userName": ctx["credential_info"]["user_info"].get("name", ctx["uname"]),
        "displayName": ctx["credential_info"]["user_info"].get("display_name", ctx["uname"]),
        "credentialId": ctx["credential_id_b64"],
        "credentialIdBase64Url": ctx["credential_id_b64u"],
        "credentialIdHex": ctx["credential_id_hex"],
        "aaguid": simple_module.base64.urlsafe_b64encode(ctx["aaguid_bytes"]).decode("ascii").rstrip("=")
        if ctx["aaguid_bytes"]
        else None,
        "aaguidHex": ctx["aaguid_bytes"].hex() if ctx["aaguid_bytes"] else None,
        "publicKey": simple_module.base64.b64encode(ctx["public_key_bytes"]).decode("ascii"),
        "publicKeyBase64Url": simple_module.base64.urlsafe_b64encode(ctx["public_key_bytes"]).decode("ascii").rstrip("="),
        "publicKeyAlgorithm": ctx["credential_info"].get("publicKeyAlgorithm") or ctx["algo"],
        "signCount": getattr(ctx["auth_data"], "counter", 0),
        "createdAt": ctx["credential_info"]["registration_time"],
        "clientExtensionOutputs": simple_module.convert_bytes_for_json(ctx["client_extension_results"]),
        "attestationFormat": ctx["attestation_format"],
        "attestationStatement": simple_module.convert_bytes_for_json(ctx["attestation_statement"]),
        "properties": simple_module.convert_bytes_for_json(ctx["credential_properties"]),
        "publicKeyCose": simple_module.convert_bytes_for_json(ctx["cose_public_key"]),
        "publicKeyBytes": simple_module.base64.b64encode(ctx["public_key_bytes"]).decode("ascii"),
        "authenticatorAttachment": ctx["authenticator_attachment_response"],
        "clientDataJSON": ctx["credential_info"].get("client_data_json"),
        "attestationObject": ctx["credential_info"].get("attestation_object"),
        "authenticatorData": ctx["authenticator_data_raw"],
        "authenticatorDataHex": ctx["authenticator_data_hex"],
        "authenticatorDataHash": ctx["authenticator_data_hash"] or None,
        "relyingParty": simple_module.make_json_safe(ctx["rp_info"]),
        "registrationResponse": ctx["credential_info"].get("registration_response"),
    }

    stored_credential["userHandle"] = ctx["user_handle_b64u"]
    ctx["stored_credential"] = stored_credential


def _persist_registered_credential_entry_impl(simple_module: Any, ctx: Dict[str, Any]) -> Optional[Any]:
    metadata_session_id = simple_module.ensure_metadata_session_id()
    existing_credentials = simple_module.readkey(ctx["uname"], session_id=metadata_session_id)

    credential_entry = {
        "credential_data": ctx["auth_data"].credential_data,
        "auth_data": ctx["auth_data"],
        "user_info": ctx["credential_info"]["user_info"],
        "registration_time": ctx["credential_info"]["registration_time"],
        "client_data_json": ctx["credential_info"].get("client_data_json", ""),
        "attestation_object": ctx["credential_info"].get("attestation_object", ""),
        "attestation_object_raw": ctx["credential_info"].get("attestation_object_raw", ""),
        "attestation_format": ctx["attestation_format"],
        "attestation_statement": ctx["attestation_statement"],
        "attestation_certificate": ctx["attestation_certificate_details"],
        "attestation_certificates": ctx["attestation_certificates_details"],
        "client_extension_outputs": ctx["client_extension_results"],
        "authenticator_attachment": ctx["authenticator_attachment_response"],
        "request_params": ctx["credential_info"].get("request_params", {}),
        "properties": ctx["credential_properties"],
        "relying_party": ctx["credential_info"].get("relying_party"),
        "registration_response": ctx["credential_info"].get("registration_response"),
    }

    if ctx["parsed_attestation_object"]:
        credential_entry["attestation_object_decoded"] = simple_module.make_json_safe(
            ctx["parsed_attestation_object"]
        )

    if isinstance(existing_credentials, list):
        existing_credentials.append(credential_entry)
    else:
        existing_credentials = [credential_entry]

    try:
        simple_module.savekey(ctx["uname"], existing_credentials, session_id=metadata_session_id)
    except Exception:
        simple_module.app.logger.exception("Failed to persist registered credential for %s", ctx["uname"])
        return simple_module.jsonify({"error": "Unable to persist registered credential."}), 500

    return None


def _update_session_simple_credentials_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    session_simple_credentials = simple_module.session.get("simple_credentials")
    if isinstance(session_simple_credentials, list):
        new_entry = {
            "credentialId": ctx["stored_credential"]["credentialIdBase64Url"],
            "aaguid": ctx["stored_credential"].get("aaguid"),
            "publicKey": ctx["stored_credential"]["publicKeyBase64Url"],
            "algorithm": ctx["stored_credential"].get("publicKeyAlgorithm"),
            "signCount": ctx["stored_credential"].get("signCount", 0),
            "email": ctx["stored_credential"].get("email"),
            "type": "simple",
        }
        session_simple_credentials = [
            entry for entry in session_simple_credentials if isinstance(entry, Mapping)
        ]
        session_simple_credentials.append(new_entry)
        simple_module.session["simple_credentials"] = session_simple_credentials


def _record_registration_event_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    metadata_description: Optional[str] = None
    if isinstance(ctx["metadata_summary"], Mapping):
        raw_description = ctx["metadata_summary"].get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = ctx["response"].get("transports") if isinstance(ctx["response"], Mapping) else None
    transports: Optional[List[str]] = None
    if isinstance(transports_field, list):
        transports = [str(item) for item in transports_field if isinstance(item, str)]

    event = simple_module.RegistrationEvent(
        timestamp=simple_module.datetime.now(simple_module.timezone.utc),
        rp_id=ctx["resolved_rp_id"],
        user_id=ctx["user_handle_bytes"],
        user_name=str(ctx["uname"] or ""),
        user_display_name=str(
            ctx["credential_info"]["user_info"].get("display_name") or ctx["uname"] or ""
        ),
        credential_id=ctx["credential_id_bytes"],
        public_key_cose=ctx["cose_public_key"],
        sign_count=int(getattr(ctx["auth_data"], "counter", 0)),
        transports=transports,
        aaguid=ctx["aaguid_bytes"] or None,
        device_name_mds=metadata_description,
        attestation_format=str(ctx["attestation_format"] or ""),
        attestation_object=simple_module._decode_base64url_bytes(ctx["raw_attestation_object_b64"]),
        client_data_json=simple_module._decode_base64url_bytes(ctx["client_data_json_b64"]),
        signature_valid=ctx["attestation_signature_valid"],
        root_valid=ctx["attestation_root_valid"],
        rp_id_hash_valid=ctx["attestation_rp_id_hash_valid"],
        aaguid_match=ctx["attestation_aaguid_match"],
    )

    simple_module.record_registration_event(event)


def persist_registration_context_impl(simple_module: Any, ctx: Dict[str, Any]) -> Optional[Any]:
    persist_response = _persist_registered_credential_entry_impl(simple_module, ctx)
    if persist_response is not None:
        return persist_response

    _update_session_simple_credentials_impl(simple_module, ctx)
    _record_registration_event_impl(simple_module, ctx)
    return None


def build_register_complete_response_payload_impl(simple_module: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
    response_payload: Dict[str, Any] = {
        "status": "OK",
        "algo": ctx["algoname"],
        **ctx["debug_info"],
        "storedCredential": simple_module.convert_bytes_for_json(ctx["stored_credential"]),
        "relyingParty": ctx["rp_info"],
    }
    if ctx["warnings"]:
        response_payload["warnings"] = ctx["warnings"]
    return response_payload
