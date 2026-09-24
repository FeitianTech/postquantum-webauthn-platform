from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Mapping, MutableMapping
from datetime import datetime, timezone
from typing import Any

from flask import jsonify, request, session

from fido2 import cbor
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ... import (
    config,
    credential_artifacts,
    device_logs,
)
from ...attachments import (
    normalize_attachment,
    normalize_attachment_list,
    resolve_effective_attachments,
)
from ...encoding import decode_hex, encode_base64, encode_base64url
from ...storage import credentials
from ...webauthn import attestation, metadata, pqc
from .. import binary_helpers
from . import algorithms, binary, summary, tracing

logger = logging.getLogger(__name__)


def prepare_register_complete_inputs(
    data: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, Any | None]:
    response = data.get("__credential_response")
    if not response:
        return None, (jsonify({"error": "Credential response is required"}), 400)

    credential_response = response.get("response", {}) if isinstance(response, dict) else {}
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    original_public_key = original_request.get("publicKey") if isinstance(original_request, Mapping) else None
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

    request_allowed_attachments = resolve_effective_attachments(
        original_hints,
        requested_attachment,
    )

    session_allowed_marker = session.pop("advanced_register_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = normalize_attachment_list(session_allowed_marker)
    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    response_attachment = normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )
    if allowed_attachments:
        if response_attachment is None:
            return None, (
                jsonify(
                    {
                        "error": "Authenticator attachment could not be determined to enforce selected hints.",
                    }
                ),
                400,
            )
        if response_attachment not in allowed_attachments:
            return None, (
                jsonify(
                    {"error": "Authenticator attachment is not permitted by the selected hints."}
                ),
                400,
            )

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

    metadata_session_id = metadata.ensure_metadata_session_id()

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
    ) = attestation.extract_attestation_details(response)

    attestation_object_b64 = credential_response.get("attestationObject")
    raw_attestation_object = parsed_attestation_object or attestation_object_b64
    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = parsed_client_data_json or client_data_json_b64

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = attestation.extract_min_pin_length(client_extension_results)
    authenticator_attachment_response = normalize_attachment(
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


CHALLENGE_SOURCE_SERVER = "server-session"
#: The ceremony challenge was taken from the request body (request-editor mode).
CHALLENGE_SOURCE_CLIENT = "client-supplied"


def resolve_state_and_registration_server(
    *,
    data: Mapping[str, Any],
    original_request: Mapping[str, Any],
    public_key: Mapping[str, Any],
    response: Mapping[str, Any],
    attestation_format: Any,
    attestation_statement: Any,
    raw_attestation_object: Any,
    trace: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, Any | None]:
    state = session.pop("advanced_state", None)
    challenge_source = CHALLENGE_SOURCE_SERVER if state is not None else None
    if state is None:
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state
            challenge_source = CHALLENGE_SOURCE_CLIENT

    # Record where the challenge came from before anything below can raise, so
    # that the caller can always report it -- the advanced flow may be
    # permissive, but it must never be silent about it.
    if trace is not None and challenge_source is not None:
        trace["challengeSource"] = challenge_source

    stored_original_request = session.pop("advanced_original_request", None)
    if stored_original_request is None and isinstance(original_request, Mapping):
        stored_original_request = original_request

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

    stored_rp = session.pop("advanced_rp", None)
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")
    elif isinstance(public_key, Mapping):
        rp_candidate = public_key.get("rp")
        if isinstance(rp_candidate, Mapping):
            stored_rp_id = rp_candidate.get("id")
            stored_rp_name = rp_candidate.get("name")
        rp_id_candidate = public_key.get("rpId")
        if stored_rp_id is None and isinstance(rp_id_candidate, str):
            stored_rp_id = rp_id_candidate

    resolved_rp_id = config.determine_rp_id(stored_rp_id)
    register_server = config.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)
    auth_data = register_server.register_complete(state, response)

    tracing._log_authenticator_attestation_response(
        attestation_format,
        auth_data,
        attestation_statement,
        raw_attestation_object,
    )

    return {
        "state": state,
        "storedOriginalRequest": stored_original_request,
        "resolvedRpId": resolved_rp_id,
        "authData": auth_data,
        "challengeSource": challenge_source,
    }, None


def build_registration_material(
    *,
    auth_data: Any,
    attestation_format: Any,
    attestation_statement: Any,
    attestation_certificate_details: Any,
    attestation_certificates_details: Any,
    client_extension_results: Any,
    credential_info: dict[str, Any],
    response: Any,
    user_handle: bytes,
    resolved_rp_id: str,
    resident_key_required: bool,
    attestation_rp_id_hash_valid: Any,
    attestation_checks_safe: Any,
    attestation_summary: Any,
) -> dict[str, Any]:
    credential_data = auth_data.credential_data
    credential_id_bytes = getattr(credential_data, "credential_id", b"") or b""
    credential_id_hex = credential_id_bytes.hex() if credential_id_bytes else None
    credential_id_b64 = (
        encode_base64(credential_id_bytes) if credential_id_bytes else None
    )
    credential_id_b64url = (
        encode_base64url(credential_id_bytes)
        if credential_id_bytes
        else None
    )

    aaguid_hex = None
    aaguid_guid = None
    aaguid_bytes: bytes | None = None
    aaguid_value = getattr(credential_data, "aaguid", None)
    if aaguid_value is not None:
        try:
            aaguid_bytes = bytes(aaguid_value)
        except (TypeError, ValueError):
            aaguid_bytes = None
        if aaguid_bytes is not None and len(aaguid_bytes) == 16:
            aaguid_hex = aaguid_bytes.hex()
            try:
                aaguid_guid = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                aaguid_guid = None

    if aaguid_hex:
        credential_info["properties"]["aaguid"] = aaguid_hex
        credential_info["properties"]["aaguidHex"] = aaguid_hex
    if aaguid_guid:
        credential_info["properties"]["aaguidGuid"] = aaguid_guid

    flags_dict = {
        "AT": bool(auth_data.flags & auth_data.FLAG.AT),
        "BE": bool(auth_data.flags & auth_data.FLAG.BE),
        "BS": bool(auth_data.flags & auth_data.FLAG.BS),
        "ED": bool(auth_data.flags & auth_data.FLAG.ED),
        "UP": bool(auth_data.flags & auth_data.FLAG.UP),
        "UV": bool(auth_data.flags & auth_data.FLAG.UV),
    }

    auth_data_bytes = bytes(auth_data)
    authenticator_data_hex = auth_data_bytes.hex()
    authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
    registration_timestamp = tracing.datetime_from_timestamp(credential_info["registration_time"])

    rp_id_hash_hex = ""
    rp_id_hash_b64 = ""
    try:
        rp_id_hash_bytes = bytes(getattr(auth_data, "rp_id_hash", b""))
    except (TypeError, ValueError):
        rp_id_hash_bytes = b""
    else:
        rp_id_hash_hex = rp_id_hash_bytes.hex()
        rp_id_hash_b64 = encode_base64url(rp_id_hash_bytes)

    expected_rp_hash_bytes = hashlib.sha256((resolved_rp_id or "").encode("utf-8")).digest()
    expected_rp_hash_hex = expected_rp_hash_bytes.hex()
    expected_rp_hash_b64 = encode_base64url(expected_rp_hash_bytes)

    if attestation_rp_id_hash_valid is None:
        attestation_rp_id_hash_valid = rp_id_hash_bytes == expected_rp_hash_bytes

    if rp_id_hash_hex:
        credential_info["properties"]["rpIdHash"] = rp_id_hash_hex
    if rp_id_hash_b64:
        credential_info["properties"]["rpIdHashBase64"] = rp_id_hash_b64
    credential_info["properties"]["rpIdHashExpected"] = expected_rp_hash_hex
    credential_info["properties"]["rpIdHashExpectedBase64"] = expected_rp_hash_b64

    cred_props = (
        client_extension_results.get("credProps") if isinstance(client_extension_results, dict) else None
    )
    if isinstance(cred_props, dict) and "rk" in cred_props:
        resident_key_result = bool(cred_props.get("rk"))
    elif isinstance(cred_props, bool):
        resident_key_result = bool(cred_props)
    else:
        resident_key_result = bool(auth_data.flags & auth_data.FLAG.BE) or bool(resident_key_required)

    credential_info["properties"]["residentKey"] = bool(resident_key_result)
    credential_info["resident_key"] = bool(resident_key_result)
    credential_info["properties"]["authenticatorDataHash"] = authenticator_data_hash

    large_blob_result = False
    if isinstance(client_extension_results, dict) and "largeBlob" in client_extension_results:
        large_blob_value = client_extension_results.get("largeBlob")
        if isinstance(large_blob_value, dict):
            large_blob_result = bool(
                large_blob_value.get("supported")
                or large_blob_value.get("written")
                or large_blob_value.get("blob")
                or large_blob_value.get("result")
            )
        else:
            large_blob_result = bool(large_blob_value)

    rp_info = {
        "aaguid": {"raw": aaguid_hex, "guid": aaguid_guid},
        "attestationFmt": attestation_format,
        "attestationObject": credential_info.get("attestation_object"),
        "createdAt": registration_timestamp,
        "credentialId": credential_id_hex,
        "credentialIdBase64": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64url,
        "rpIdHash": rp_id_hash_hex,
        "rpIdHashBase64": rp_id_hash_b64,
        "rpIdHashExpected": expected_rp_hash_hex,
        "rpIdHashExpectedBase64": expected_rp_hash_b64,
        "rpIdHashMatch": bool(attestation_rp_id_hash_valid),
        "authenticatorDataHash": authenticator_data_hash,
        "device": {"name": "Unknown device", "type": "unknown"},
        "largeBlob": large_blob_result,
        "publicKeyAlgorithm": credential_info.get("publicKeyAlgorithm"),
        "registrationData": {
            "authenticatorData": authenticator_data_hex,
            "authenticatorDataHash": authenticator_data_hash,
            "clientExtensionResults": credentials.convert_bytes_for_json(client_extension_results),
            "flags": flags_dict,
            "signatureCounter": auth_data.counter,
            "attestationChecks": attestation_checks_safe,
            "attestationSummary": attestation_summary,
        },
        "residentKey": resident_key_result,
        "userHandle": {
            "base64": encode_base64(user_handle),
            "base64url": encode_base64url(user_handle),
            "hex": user_handle.hex(),
        },
    }

    if attestation_certificate_details:
        rp_info["attestationCertificate"] = attestation_certificate_details
    if attestation_certificates_details:
        rp_info["attestationCertificates"] = attestation_certificates_details

    credential_info["relying_party"] = attestation.make_json_safe(rp_info)

    user_handle_b64url = encode_base64url(user_handle)
    user_handle_b64 = encode_base64(user_handle)

    stored_properties = credentials.convert_bytes_for_json(credential_info.get("properties", {}))
    stored_extensions = credentials.convert_bytes_for_json(client_extension_results)

    public_key_b64 = None
    public_key_b64url = None
    credential_public_key = getattr(auth_data.credential_data, "public_key", None)
    if isinstance(credential_public_key, Mapping):
        try:
            public_key_cbor_bytes = cbor.encode(dict(credential_public_key))
        except Exception:
            public_key_cbor_bytes = None
        if public_key_cbor_bytes:
            public_key_b64 = encode_base64(public_key_cbor_bytes)
            public_key_b64url = encode_base64url(public_key_cbor_bytes)

    stored_credential: dict[str, Any] = {
        "type": "advanced",
        "userName": credential_info["user_info"]["name"],
        "displayName": credential_info["user_info"]["display_name"],
        "residentKey": bool(resident_key_result),
        "largeBlob": bool(large_blob_result),
        "authenticatorAttachment": credential_info.get("authenticator_attachment"),
        "credentialId": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64url,
        "credentialIdHex": credential_id_hex,
        "aaguid": encode_base64url(aaguid_bytes) if aaguid_bytes else None,
        "aaguidHex": aaguid_hex,
        "aaguidGuid": aaguid_guid,
        "publicKeyAlgorithm": credential_info.get("publicKeyAlgorithm"),
        "publicKey": public_key_b64,
        "publicKeyBase64": public_key_b64,
        "publicKeyBase64Url": public_key_b64url,
        "publicKeyBytes": credential_info.get("publicKeyBytes"),
        "publicKeyCose": credential_info.get("publicKeyCose"),
        "publicKeyType": credential_info.get("publicKeyType"),
        "signCount": getattr(auth_data, "counter", 0),
        "createdAt": credential_info["registration_time"],
        "clientExtensionOutputs": stored_extensions,
        "attestationFormat": attestation_format,
        "attestationStatement": credentials.convert_bytes_for_json(attestation_statement),
        "attestationObject": credentials.convert_bytes_for_json(credential_info.get("attestation_object")),
        "authenticatorData": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash,
        "clientDataJSON": credentials.convert_bytes_for_json(credential_info.get("client_data_json")),
        "relyingParty": attestation.make_json_safe(rp_info),
        "properties": stored_properties,
        "registrationResponse": credential_info.get("registration_response"),
        "userHandle": user_handle_b64,
        "userHandleBase64": user_handle_b64,
        "userHandleBase64Url": user_handle_b64url,
        "userHandleHex": user_handle.hex(),
    }

    stored_credential = credentials.convert_bytes_for_json(
        {k: v for k, v in stored_credential.items() if v is not None}
    )

    return {
        "storedCredential": stored_credential,
        "rpInfo": rp_info,
        "credentialIdBytes": credential_id_bytes,
        "aaguidBytes": aaguid_bytes,
    }


def finalize_registration_completion(
    *,
    stored_credential: dict[str, Any],
    rp_info: dict[str, Any],
    metadata_summary: Any,
    response: Any,
    metadata_session_id: str,
    username: str,
    warnings: list[str],
    debug_info: dict[str, Any],
    algoname: str,
    resolved_rp_id: str,
    credential_id_bytes: bytes,
    aaguid_bytes: bytes | None,
    auth_data: Any,
    attestation_format: Any,
    attestation_object_b64: Any,
    client_data_json_b64: Any,
    user_handle: bytes,
    display_name: str,
) -> Any:
    artifact_record = json.loads(json.dumps(stored_credential))
    storage_id_source = (
        artifact_record.get("credentialIdBase64Url")
        or artifact_record.get("credentialIdHex")
        or ""
    )
    storage_id = summary._generate_storage_id(str(storage_id_source))

    artifact_payload = {"schemaVersion": 1, "storedCredential": artifact_record}
    try:
        artifact_stored = credential_artifacts.store_credential_artifact(
            storage_id,
            artifact_payload,
            session_id=metadata_session_id,
        )
    except Exception:
        logger.exception(
            "Failed to store advanced credential artifact for user %s",
            username,
        )
        return jsonify({"error": "Unable to persist credential artifact."}), 500

    if not artifact_stored:
        logger.error(
            "Advanced credential artifact was not stored for user %s",
            username,
        )
        return jsonify({"error": "Unable to persist credential artifact."}), 500

    summary_credential = summary._summarize_stored_credential(artifact_record, storage_id)

    metadata_description: str | None = None
    if isinstance(metadata_summary, Mapping):
        raw_description = metadata_summary.get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = response.get("transports") if isinstance(response, Mapping) else None
    transports: list[str] | None = None
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

    event = device_logs.RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
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
        attestation_object=binary_helpers.decode_base64url_bytes(attestation_object_b64),
        client_data_json=binary_helpers.decode_base64url_bytes(client_data_json_b64),
    )

    device_logs.record_registration_event(event)

    response_payload: dict[str, Any] = {
        "status": "OK",
        "algo": algoname,
        **debug_info,
        "relyingParty": rp_info,
        "storedCredential": summary_credential,
    }
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(response_payload)


def advanced_register_complete():
    data = request.get_json(silent=True) or {}
    prepared, error_response = prepare_register_complete_inputs(data)
    if error_response is not None:
        return error_response
    if prepared is None:
        return jsonify({"error": "Invalid request"}), 400

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

    warnings: list[str] = []

    # Always reported, even on the error paths below: the advanced flow is
    # allowed to be permissive, but never allowed to be silent about it.
    state_trace: dict[str, Any] = {"challengeSource": CHALLENGE_SOURCE_CLIENT}

    try:
        state_ctx, state_error = resolve_state_and_registration_server(data=data,
            original_request=original_request,
            public_key=public_key,
            response=response if isinstance(response, Mapping) else {},
            attestation_format=attestation_format,
            attestation_statement=attestation_statement,
            raw_attestation_object=raw_attestation_object,
            trace=state_trace,
        )
        if state_error is not None:
            return _with_challenge_source(state_error, state_trace)
        if state_ctx is None:
            return jsonify(
                {
                    "error": "Registration state not found",
                    "challengeSource": state_trace["challengeSource"],
                }
            ), 400

        state = state_ctx["state"]
        stored_original_request = state_ctx["storedOriginalRequest"]
        resolved_rp_id = state_ctx["resolvedRpId"]
        auth_data = state_ctx["authData"]

        stored_public_key: Mapping[str, Any] | None = None
        if isinstance(stored_original_request, Mapping):
            stored_public_key = stored_original_request.get("publicKey")
            if not isinstance(stored_public_key, Mapping):
                stored_public_key = None

        public_key_for_checks: Mapping[str, Any] | None = (
            stored_public_key if isinstance(stored_public_key, Mapping) else public_key
        )

        # The origin the ceremony claims, read from clientDataJSON -- NOT from
        # the request's own Origin header, which the caller also controls.
        ceremony_origin = config.extract_client_data_origin(
            response.get("response") if isinstance(response, Mapping) else None
        )
        if not config.is_origin_allowed(ceremony_origin):
            return jsonify(
                {
                    "error": (
                        "Ceremony origin is not permitted by the configured "
                        "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                    ),
                    "challengeSource": state_trace["challengeSource"],
                }
            ), 400

        expected_origin = config.determine_expected_origin(ceremony_origin) or (
            request.host_url.rstrip("/")
        )
        attestation_checks = attestation.perform_attestation_checks(
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
        attestation_checks_safe = attestation.make_json_safe(attestation_checks)

        attestation_warnings = attestation_checks.get("warnings")
        if isinstance(attestation_warnings, list):
            for message in attestation_warnings:
                if isinstance(message, str):
                    stripped = message.strip()
                    if stripped:
                        warnings.append(stripped)

        attestation_errors: list[str] = []
        raw_attestation_errors = attestation_checks.get("errors")
        if isinstance(raw_attestation_errors, list):
            attestation_errors = [
                str(message) for message in raw_attestation_errors if str(message).strip()
            ]

        attestation_summary = {
            "signatureValid": attestation_signature_valid,
            "rootValid": attestation_root_valid,
            "rpIdHashValid": attestation_rp_id_hash_valid,
            "aaguidMatch": attestation_aaguid_match,
            "errors": attestation_errors,
            "verified": not attestation_errors,
        }
        pqc_signature_valid = attestation_checks.get("pqc_signature_valid")
        if pqc_signature_valid is not None:
            attestation_summary["pqcSignatureValid"] = pqc_signature_valid
        metadata_summary = attestation_checks_safe.get("metadata")
        if isinstance(metadata_summary, Mapping):
            attestation_summary["metadata"] = metadata_summary
        warnings_summary = attestation_checks_safe.get("warnings")
        if isinstance(warnings_summary, list) and warnings_summary:
            attestation_summary["warnings"] = warnings_summary

        authenticator_extensions_summary: dict[str, Any] = {}
        if hasattr(auth_data, "extensions"):
            authenticator_extensions = getattr(auth_data, "extensions")
            if isinstance(authenticator_extensions, Mapping):
                authenticator_extensions_summary = attestation.summarize_authenticator_extensions(
                    authenticator_extensions
                )

        user_id_value = user_info.get("id", "")
        if user_id_value:
            try:
                user_handle = binary._extract_binary_value(user_id_value)
                if isinstance(user_handle, str):
                    user_handle = decode_hex(user_handle)
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
            "registration_time": time.time(),
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

        credentials.add_public_key_material(credential_info, getattr(auth_data.credential_data, "public_key", {}))
        attestation.augment_aaguid_fields(credential_info)
        if authenticator_extensions_summary:
            credential_info["authenticator_extensions"] = authenticator_extensions_summary
        if attestation_certificate_details is not None:
            credential_info["attestation_certificate"] = attestation_certificate_details
        if isinstance(response, Mapping):
            credential_info["registration_response"] = attestation.make_json_safe(response)

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

        algo = algorithms._coerce_cose_algorithm(raw_alg_value)
        credential_info["publicKeyAlgorithm"] = algo
        algoname = pqc.describe_algorithm(algo)
        pqc.log_algorithm_selection("registration", algo)

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
            "attestationErrors": attestation_errors,
            "attestationVerified": not attestation_errors,
            "challengeSource": state_trace["challengeSource"],
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

        material = build_registration_material(auth_data=auth_data,
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
            material["rpInfo"]["registrationData"]["authenticatorExtensions"] = attestation.make_json_safe(
                authenticator_extensions_summary
            )

        return finalize_registration_completion(stored_credential=material["storedCredential"],
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
        return jsonify(
            {
                "error": str(exc),
                "challengeSource": state_trace["challengeSource"],
            }
        ), 400


def _with_challenge_source(
    error_response: Any,
    state_trace: Mapping[str, Any],
) -> Any:
    """Re-emit an early error response with the challenge source attached."""

    payload, status = error_response if isinstance(error_response, tuple) else (error_response, 200)
    try:
        body = payload.get_json(silent=True) or {}
    except Exception:
        return error_response
    if not isinstance(body, Mapping):
        return error_response
    merged = dict(body)
    merged.setdefault("challengeSource", state_trace.get("challengeSource"))
    return jsonify(merged), status


def configure_allowed_algorithms(
    public_key: Mapping[str, Any],
    temp_server: Any,
    warnings: list[str],
) -> None:
    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        allowed_algorithms: list[Any] = []
        normalized_params: list[dict[str, Any]] = []
        for param in pub_key_cred_params:
            raw_alg_value: Any
            if isinstance(param, Mapping):
                raw_alg_value = param.get("alg")
                if raw_alg_value is None:
                    raw_alg_value = param.get("id")
                if raw_alg_value is None:
                    raw_alg_value = param.get("value")

                type_value = param.get("type")
                if isinstance(type_value, str):
                    if type_value.strip().lower() != "public-key":
                        continue
                elif type_value is not None:
                    continue

                alg_value = algorithms._coerce_cose_algorithm(raw_alg_value)
                if alg_value is None:
                    continue
                normalized_params.append({"type": "public-key", "alg": alg_value})
            else:
                alg_value = algorithms._coerce_cose_algorithm(param)
                if alg_value is None:
                    continue
                normalized_params.append({"type": "public-key", "alg": alg_value})

            allowed_algorithms.append(
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=alg_value,
                )
            )

        if normalized_params:
            public_key["pubKeyCredParams"] = normalized_params
        if allowed_algorithms:
            temp_server.allowed_algorithms = allowed_algorithms
    else:
        temp_server.allowed_algorithms = [
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-50,
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-48,
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-49,
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7,
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-257,
            ),
        ]

    allowed_algorithm_ids = [
        getattr(param, "alg", None)
        for param in getattr(temp_server, "allowed_algorithms", [])
    ]
    allowed_algorithm_ids = [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    pqc_in_allowed = {alg for alg in allowed_algorithm_ids if pqc.is_pqc_algorithm(alg)}
    if not pqc_in_allowed:
        return

    pqc_available_ids, pqc_error_message = pqc.detect_available_pqc_algorithms()
    missing_pqc = pqc_in_allowed - pqc_available_ids
    if not missing_pqc:
        return

    missing_names = ", ".join(
        pqc.PQC_ALGORITHM_ID_TO_NAME[alg] for alg in sorted(missing_pqc)
    )
    if pqc_error_message:
        logger.warning("Post-quantum support unavailable: %s", pqc_error_message)
    else:
        logger.warning(
            "Post-quantum algorithms requested (%s) but not available in this environment.",
            missing_names,
        )

    filtered_allowed = [
        param for param in temp_server.allowed_algorithms if getattr(param, "alg", None) not in missing_pqc
    ]
    fallback_applied = False
    if not filtered_allowed:
        temp_server.allowed_algorithms = [
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=alg_value,
            )
            for alg_value in (-7, -8, -257)
        ]
        fallback_applied = True
    else:
        temp_server.allowed_algorithms = filtered_allowed

    if fallback_applied:
        warnings.append(
            f"Unsupported PQC algorithms were skipped ({missing_names}); falling back to classical algorithms."
        )
    else:
        warnings.append(f"Unsupported PQC algorithms were skipped ({missing_names}).")


def build_exclude_list(public_key: Mapping[str, Any]) -> list[Any]:
    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = binary._extract_binary_value(exclude_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = decode_hex(cred_id)
                if cred_id:
                    exclude_list.append(
                        PublicKeyCredentialDescriptor(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            id=cred_id,
                        )
                    )
    return exclude_list


def build_processed_extensions(public_key: Mapping[str, Any]) -> dict[str, Any]:
    extensions = public_key.get("extensions", {})
    processed_extensions: dict[str, Any] = {}

    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            if isinstance(ext_value, int):
                protect_map = {
                    1: "userVerificationOptional",
                    2: "userVerificationOptionalWithCredentialIDList",
                    3: "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = protect_map.get(ext_value, ext_value)
            elif isinstance(ext_value, str):
                alias_map = {
                    "userVerificationOptional": "userVerificationOptional",
                    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationRequired": "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = alias_map.get(ext_value, ext_value)
            else:
                processed_extensions["credentialProtectionPolicy"] = ext_value
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredentialProtectionPolicy"] = bool(ext_value)
        elif ext_name == "largeBlob":
            processed_extensions["largeBlob"] = {"support": ext_value} if isinstance(ext_value, str) else ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if isinstance(prf_eval, dict):
                    if "first" in prf_eval:
                        first_value = binary._extract_binary_value(prf_eval["first"])
                        if isinstance(first_value, str):
                            first_value = decode_hex(first_value)
                        processed_eval["first"] = first_value
                    if "second" in prf_eval:
                        second_value = binary._extract_binary_value(prf_eval["second"])
                        if isinstance(second_value, str):
                            second_value = decode_hex(second_value)
                        processed_eval["second"] = second_value
                processed_extensions["prf"] = {"eval": processed_eval} if processed_eval else ext_value
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    return processed_extensions


def advanced_register_begin():
    data = request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return jsonify(
            {"error": "Invalid request: Missing publicKey in CredentialCreationOptions"},
        ), 400

    public_key = data["publicKey"]

    warnings: list[str] = []

    if not public_key.get("rp"):
        return jsonify({"error": "Missing required field: rp"}), 400
    if not public_key.get("user"):
        return jsonify({"error": "Missing required field: user"}), 400
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    user_info = public_key["user"]
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)

    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400

    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            user_id_bytes = binary._extract_binary_value(user_id_value)
            if isinstance(user_id_bytes, str):
                user_id_bytes = decode_hex(user_id_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid user ID format: {exc}"}), 400
    else:
        user_id_bytes = username.encode("utf-8")

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = binary._extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = decode_hex(challenge_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    rp_input = public_key.get("rp") if isinstance(public_key, Mapping) else None
    rp_entity = config.build_rp_entity(rp_input)
    sanitized_rp = {"id": rp_entity.id, "name": rp_entity.name}
    if isinstance(rp_input, Mapping):
        sanitized_rp.update({k: v for k, v in rp_input.items() if k not in {"id", "name"}})
    if isinstance(public_key, MutableMapping):
        public_key["rp"] = sanitized_rp

    temp_server = config.create_fido_server(rp_data=sanitized_rp)

    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None

    attestation_preference = public_key.get("attestation", "none")
    if attestation_preference == "direct":
        temp_server.attestation = AttestationConveyancePreference.DIRECT
    elif attestation_preference == "indirect":
        temp_server.attestation = AttestationConveyancePreference.INDIRECT
    elif attestation_preference == "enterprise":
        temp_server.attestation = AttestationConveyancePreference.ENTERPRISE
    else:
        temp_server.attestation = AttestationConveyancePreference.NONE

    configure_allowed_algorithms(public_key,
        temp_server,
        warnings,
    )

    public_key["pubKeyCredParams"] = [
        {
            "type": (
                getattr(param.type, "value", param.type)
                if hasattr(param, "type")
                else "public-key"
            ),
            "alg": getattr(param, "alg", None),
        }
        for param in temp_server.allowed_algorithms
        if getattr(param, "alg", None) is not None
    ]

    logger.info(
        "Advanced registration request will advertise algorithms: %s",
        [entry.get("alg") for entry in public_key["pubKeyCredParams"]],
    )

    auth_selection = public_key.get("authenticatorSelection", {})
    if not isinstance(auth_selection, dict):
        auth_selection = {}
        public_key["authenticatorSelection"] = auth_selection

    raw_hints = public_key.get("hints")
    hints_list: list[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    requested_attachment = normalize_attachment(
        auth_selection.get("authenticatorAttachment")
    )
    allowed_attachment_values = resolve_effective_attachments(
        hints_list,
        requested_attachment,
    )
    session["advanced_register_allowed_attachments"] = list(allowed_attachment_values)

    uv_req = UserVerificationRequirement.PREFERRED
    user_verification = auth_selection.get("userVerification", "preferred")
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED

    auth_attachment = None
    attachment_source = requested_attachment
    if not attachment_source and len(allowed_attachment_values) == 1:
        attachment_source = allowed_attachment_values[0]
    if attachment_source == "platform":
        auth_attachment = AuthenticatorAttachment.PLATFORM
    elif attachment_source == "cross-platform":
        auth_attachment = AuthenticatorAttachment.CROSS_PLATFORM

    rk_req = ResidentKeyRequirement.PREFERRED
    resident_key = auth_selection.get("residentKey", "preferred")
    if auth_selection.get("requireResidentKey") is True:
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "required":
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "discouraged":
        rk_req = ResidentKeyRequirement.DISCOURAGED

    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes,
        name=username,
        display_name=display_name,
    )

    exclude_list = build_exclude_list(public_key)
    processed_extensions = build_processed_extensions(public_key)

    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    session["advanced_state"] = state
    session["advanced_rp"] = {"id": rp_entity.id, "name": rp_entity.name}
    session["advanced_original_request"] = data

    response_payload = dict(options)
    response_payload["__session_state"] = attestation.make_json_safe(state)
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(attestation.make_json_safe(response_payload))
