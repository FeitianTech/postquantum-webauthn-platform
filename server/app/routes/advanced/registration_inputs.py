"""Advanced registration complete: what the request carries, and fido2's verdict on it.

``prepare_register_complete_inputs`` reads the request (attachment hints, user,
resident-key requirement, attestation and client data) and
``resolve_state_and_registration_server`` picks the ceremony state and RP and
has fido2 verify the registration. Both answer 400 for a request that cannot go
further; the order of their session reads is part of the route's behaviour.
"""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from flask import jsonify, session

from ... import visitor_session
from ...config import relying_party
from ...webauthn.attachments import (
    attachment_hint_violation,
    normalize_attachment,
    resolve_allowed_attachments,
    resolve_effective_attachments,
)
from ...webauthn.attestation import aaguid as attestation_aaguid
from ...webauthn.attestation import certificates as attestation_certificates


def _request_allowed_attachments(original_public_key: Any) -> list[str]:
    """The attachments the request's own hints and authenticatorSelection allow."""

    original_hints: list[str] = []
    if isinstance(original_public_key, Mapping):
        raw_hints = original_public_key.get("hints")
        if isinstance(raw_hints, list):
            original_hints = [item for item in raw_hints if isinstance(item, str)]

    requested_attachment = None
    if isinstance(original_public_key, Mapping):
        selection = original_public_key.get("authenticatorSelection")
        if isinstance(selection, Mapping):
            requested_attachment = normalize_attachment(selection.get("authenticatorAttachment"))

    return resolve_effective_attachments(original_hints, requested_attachment)


def _resident_key_requirement(public_key: Any) -> tuple[Any, bool]:
    """``residentKey`` as requested, and whether a resident key was required."""

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
    return resident_key_requested, bool(resident_key_required)


def _attestation_inputs(response: Any, credential_response: Mapping[str, Any]) -> dict[str, Any]:
    """The attestation, client data and extension outputs the credential response carries."""

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = attestation_certificates.extract_attestation_details(response)

    attestation_object_b64 = credential_response.get("attestationObject")
    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    return {
        "attestationFormat": attestation_format,
        "attestationStatement": attestation_statement,
        "attestationCertificateDetails": attestation_certificate_details,
        "attestationCertificatesDetails": attestation_certificates_details,
        "attestationObjectB64": attestation_object_b64,
        "rawAttestationObject": parsed_attestation_object or attestation_object_b64,
        "clientDataJsonB64": client_data_json_b64,
        "clientDataJson": parsed_client_data_json or client_data_json_b64,
        "clientExtensionResults": client_extension_results,
        "minPinLengthValue": attestation_aaguid.extract_min_pin_length(client_extension_results),
        "authenticatorAttachmentResponse": normalize_attachment(
            response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
        ),
    }


def prepare_register_complete_inputs(
    data: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, Any | None]:
    response = data.get("__credential_response")
    if not response:
        return None, (jsonify({"error": "Credential response is required"}), 400)

    credential_response = response.get("response", {}) if isinstance(response, dict) else {}
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    original_public_key = original_request.get("publicKey") if isinstance(original_request, Mapping) else None
    request_allowed_attachments = _request_allowed_attachments(original_public_key)
    allowed_attachments = resolve_allowed_attachments(
        session.pop("advanced_register_allowed_attachments", None),
        request_allowed_attachments,
    )
    violation = attachment_hint_violation(
        allowed_attachments,
        normalize_attachment(response.get("authenticatorAttachment") if isinstance(response, Mapping) else None),
    )
    if violation is not None:
        return None, (jsonify({"error": violation}), 400)

    if not original_request.get("publicKey"):
        return None, (
            jsonify(
                {"error": "Invalid request: Missing publicKey in JSON editor content"}
            ),
            400,
        )

    public_key = original_request["publicKey"]
    user_info = public_key.get("user", {})
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)
    if not username:
        return None, (jsonify({"error": "Username is required in user.name"}), 400)

    metadata_session_id = visitor_session.ensure_id()
    resident_key_requested, resident_key_required = _resident_key_requirement(public_key)

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
        "residentKeyRequired": resident_key_required,
        **_attestation_inputs(response, credential_response),
    }, None


def _registration_rp() -> tuple[Any, Any]:
    """The RP id and name begin kept in the session."""

    stored_rp = session.pop("advanced_rp", None)
    if isinstance(stored_rp, Mapping):
        return stored_rp.get("id"), stored_rp.get("name")
    return None, None


def resolve_state_and_registration_server(
    *,
    response: Mapping[str, Any],
    session_state: Any = None,
) -> tuple[dict[str, Any] | None, Any | None]:
    # The caller has already taken the session's state, and consumed its challenge.
    state = session_state
    stored_original_request = session.pop("advanced_original_request", None)

    if state is None:
        return None, (
            jsonify(
                {
                    "error": (
                        "Registration state not found or has expired. "
                        "Please restart the registration process."
                    )
                }
            ),
            400,
        )

    stored_rp_id, stored_rp_name = _registration_rp()
    resolved_rp_id = relying_party.determine_rp_id(stored_rp_id)
    register_server = relying_party.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)
    auth_data = register_server.register_complete(state, response)

    return {
        "state": state,
        "storedOriginalRequest": stored_original_request,
        "resolvedRpId": resolved_rp_id,
        "authData": auth_data,
    }, None
