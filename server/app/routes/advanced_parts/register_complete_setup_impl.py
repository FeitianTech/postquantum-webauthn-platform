from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple


def prepare_register_complete_inputs(
    advanced_module: Any,
    data: Mapping[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Any]]:
    response = data.get("__credential_response")
    if not response:
        return None, (advanced_module.jsonify({"error": "Credential response is required"}), 400)

    credential_response = response.get("response", {}) if isinstance(response, dict) else {}
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    original_public_key = original_request.get("publicKey") if isinstance(original_request, Mapping) else None
    original_hints: List[str] = []
    if isinstance(original_public_key, Mapping):
        raw_hints = original_public_key.get("hints")
        if isinstance(raw_hints, list):
            original_hints = [item for item in raw_hints if isinstance(item, str)]

    requested_attachment = None
    if isinstance(original_public_key, Mapping):
        selection = original_public_key.get("authenticatorSelection")
        if isinstance(selection, Mapping):
            requested_attachment = advanced_module.normalize_attachment(selection.get("authenticatorAttachment"))

    request_allowed_attachments = advanced_module.resolve_effective_attachments(
        original_hints,
        requested_attachment,
    )

    session_allowed_marker = advanced_module.session.pop("advanced_register_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = advanced_module.normalize_attachment_list(session_allowed_marker)
    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    response_attachment = advanced_module.normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )
    if allowed_attachments:
        if response_attachment is None:
            return None, (
                advanced_module.jsonify(
                    {
                        "error": "Authenticator attachment could not be determined to enforce selected hints.",
                    }
                ),
                400,
            )
        if response_attachment not in allowed_attachments:
            return None, (
                advanced_module.jsonify(
                    {"error": "Authenticator attachment is not permitted by the selected hints."}
                ),
                400,
            )

    if not original_request.get("publicKey"):
        return None, (
            advanced_module.jsonify(
                {"error": "Invalid request: Missing publicKey in JSON editor content"}
            ),
            400,
        )

    public_key = original_request["publicKey"]
    user_info = public_key.get("user", {})
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)
    if not username:
        return None, (advanced_module.jsonify({"error": "Username is required in user.name"}), 400)

    metadata_session_id = advanced_module.ensure_metadata_session_id()
    advanced_module.readkey(username, session_id=metadata_session_id)

    auth_selection = public_key.get("authenticatorSelection", {})
    if isinstance(auth_selection, Mapping):
        auth_selection = dict(auth_selection)
        if isinstance(public_key, MutableMapping):
            public_key["authenticatorSelection"] = auth_selection
    elif isinstance(public_key, MutableMapping):
        public_key["authenticatorSelection"] = {}
        auth_selection = public_key["authenticatorSelection"]

    resident_key_requested = auth_selection.get("residentKey")
    resident_key_required = auth_selection.get("requireResidentKey")
    if resident_key_required is None:
        resident_key_required = resident_key_requested == "required"

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = advanced_module.extract_attestation_details(response)

    attestation_object_b64 = credential_response.get("attestationObject")
    raw_attestation_object = parsed_attestation_object or attestation_object_b64
    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = parsed_client_data_json or client_data_json_b64

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = advanced_module.extract_min_pin_length(client_extension_results)
    authenticator_attachment_response = advanced_module.normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )

    return {
        "response": response,
        "originalRequest": original_request,
        "publicKey": public_key,
        "userInfo": user_info,
        "username": username,
        "displayName": display_name,
        "metadataSessionId": metadata_session_id,
        "allowedAttachments": allowed_attachments,
        "residentKeyRequested": resident_key_requested,
        "residentKeyRequired": bool(resident_key_required),
        "attestationFormat": attestation_format,
        "attestationStatement": attestation_statement,
        "attestationCertificateDetails": attestation_certificate_details,
        "attestationCertificatesDetails": attestation_certificates_details,
        "attestationObjectB64": attestation_object_b64,
        "rawAttestationObject": raw_attestation_object,
        "clientDataJsonB64": client_data_json_b64,
        "clientDataJson": client_data_json,
        "clientExtensionResults": client_extension_results,
        "minPinLengthValue": min_pin_length_value,
        "authenticatorAttachmentResponse": authenticator_attachment_response,
    }, None
