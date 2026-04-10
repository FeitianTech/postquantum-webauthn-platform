from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional


def finalize_registration_completion(
    advanced_module: Any,
    *,
    stored_credential: Dict[str, Any],
    rp_info: Dict[str, Any],
    metadata_summary: Any,
    response: Any,
    metadata_session_id: str,
    username: str,
    warnings: List[str],
    debug_info: Dict[str, Any],
    algoname: str,
    resolved_rp_id: str,
    credential_id_bytes: bytes,
    aaguid_bytes: Optional[bytes],
    auth_data: Any,
    attestation_format: Any,
    attestation_object_b64: Any,
    client_data_json_b64: Any,
    user_handle: bytes,
    display_name: str,
) -> Any:
    artifact_record = advanced_module.json.loads(advanced_module.json.dumps(stored_credential))
    storage_id_source = (
        artifact_record.get("credentialIdBase64Url")
        or artifact_record.get("credentialIdHex")
        or ""
    )
    storage_id = advanced_module._generate_storage_id(str(storage_id_source))

    artifact_payload = {"schemaVersion": 1, "storedCredential": artifact_record}
    try:
        artifact_stored = advanced_module.store_credential_artifact(
            storage_id,
            artifact_payload,
            session_id=metadata_session_id,
        )
    except Exception:
        advanced_module.app.logger.exception(
            "Failed to store advanced credential artifact for user %s",
            username,
        )
        return advanced_module.jsonify({"error": "Unable to persist credential artifact."}), 500

    if not artifact_stored:
        advanced_module.app.logger.error(
            "Advanced credential artifact was not stored for user %s",
            username,
        )
        return advanced_module.jsonify({"error": "Unable to persist credential artifact."}), 500

    summary_credential = advanced_module._summarize_stored_credential(artifact_record, storage_id)

    metadata_description: Optional[str] = None
    if isinstance(metadata_summary, Mapping):
        raw_description = metadata_summary.get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = response.get("transports") if isinstance(response, Mapping) else None
    transports: Optional[List[str]] = None
    if isinstance(transports_field, list):
        transports = [str(item) for item in transports_field if isinstance(item, str)]

    raw_public_key = getattr(auth_data.credential_data, "public_key", {})
    if isinstance(raw_public_key, Mapping):
        cose_public_key = dict(raw_public_key)
    else:
        try:
            cose_public_key = dict(raw_public_key)
        except Exception:
            cose_public_key = {}

    event = advanced_module.RegistrationEvent(
        timestamp=advanced_module.datetime.now(advanced_module.timezone.utc),
        rp_id=resolved_rp_id,
        user_id=user_handle,
        user_name=str(username or ""),
        user_display_name=str(display_name or username or ""),
        credential_id=credential_id_bytes,
        public_key_cose=cose_public_key,
        sign_count=int(getattr(auth_data, "counter", 0)),
        transports=transports,
        aaguid=aaguid_bytes or None,
        device_name_mds=metadata_description,
        attestation_format=str(attestation_format or ""),
        attestation_object=advanced_module._decode_base64url_bytes(attestation_object_b64),
        client_data_json=advanced_module._decode_base64url_bytes(client_data_json_b64),
    )

    advanced_module.record_registration_event(event)

    response_payload: Dict[str, Any] = {
        "status": "OK",
        "algo": algoname,
        **debug_info,
        "relyingParty": rp_info,
        "storedCredential": summary_credential,
    }
    if warnings:
        response_payload["warnings"] = warnings

    return advanced_module.jsonify(response_payload)
