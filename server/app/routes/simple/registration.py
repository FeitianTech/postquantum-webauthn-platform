from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Mapping, MutableMapping
from datetime import datetime, timezone
from typing import Any

from flask import jsonify, request, session

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import PublicKeyCredentialUserEntity

from ... import (
    config,
    device_logs,
)
from ...attachments import normalize_attachment
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...encoding import encode_base64, encode_base64url
from ...storage import credentials
from ...webauthn import attestation, metadata
from .. import binary_helpers
from . import parsing


def initialize_registration_context(ctx: dict[str, Any]) -> None:
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
    warnings: list[str] = []
    if isinstance(warnings_summary, list):
        filtered_warnings: list[Any] = []
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

    credential_info: dict[str, Any] = {
        "credential_data": ctx["auth_data"].credential_data,
        "auth_data": ctx["auth_data"],
        "user_info": {
            "name": ctx["uname"],
            "display_name": ctx["uname"],
            "user_handle": ctx["uname"].encode("utf-8"),
        },
        "registration_time": time.time(),
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

    credentials.add_public_key_material(
        credential_info,
        getattr(ctx["auth_data"].credential_data, "public_key", {}),
    )

    if ctx["parsed_attestation_object"]:
        credential_info["attestation_object_decoded"] = attestation.make_json_safe(
            ctx["parsed_attestation_object"]
        )

    if ctx["attestation_certificates_details"]:
        credential_info["attestationCertificates"] = ctx["attestation_certificates_details"]
        credential_properties["attestationCertificates"] = ctx["attestation_certificates_details"]

    if isinstance(ctx["response"], Mapping):
        credential_info["registration_response"] = attestation.make_json_safe(ctx["response"])

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
                credential_properties["aaguidGuid"] = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                pass

    ctx["metadata_summary"] = metadata_summary
    ctx["warnings"] = warnings
    ctx["attestation_summary"] = attestation_summary
    ctx["credential_info"] = credential_info
    ctx["credential_properties"] = credential_properties


def populate_authenticator_data_context(ctx: dict[str, Any]) -> None:
    try:
        auth_data_bytes = bytes(ctx["auth_data"])
    except Exception:
        auth_data_bytes = b""

    authenticator_data_raw = ""
    authenticator_data_hex = ""
    authenticator_data_hash = ""
    if auth_data_bytes:
        authenticator_data_raw = encode_base64url(auth_data_bytes)
        authenticator_data_hex = auth_data_bytes.hex()
        authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
        ctx["credential_info"]["authenticator_data_raw"] = authenticator_data_raw
        ctx["credential_info"]["authenticator_data_hex"] = authenticator_data_hex
        ctx["credential_info"]["authenticator_data_hash"] = authenticator_data_hash
        ctx["credential_properties"]["authenticatorDataHash"] = authenticator_data_hash

    algo = ctx["auth_data"].credential_data.public_key[3]
    if algo == -50:
        algoname = "ML-DSA-87 (PQC)"
    elif algo == -49:
        algoname = "ML-DSA-65 (PQC)"
    elif algo == -48:
        algoname = "ML-DSA-44 (PQC)"
    elif algo == -7:
        algoname = "ES256 (ECDSA)"
    elif algo == -257:
        algoname = "RS256 (RSA)"
    else:
        algoname = "Other (Classical)"

    flags_value = getattr(ctx["auth_data"], "flags", 0)
    flags_dict = {
        "UP": bool(flags_value & getattr(ctx["auth_data"].FLAG, "UP", 0)),
        "UV": bool(flags_value & getattr(ctx["auth_data"].FLAG, "UV", 0)),
        "BE": bool(flags_value & getattr(ctx["auth_data"].FLAG, "BE", 0)),
        "BS": bool(flags_value & getattr(ctx["auth_data"].FLAG, "BS", 0)),
        "AT": bool(flags_value & getattr(ctx["auth_data"].FLAG, "AT", 0)),
        "ED": bool(flags_value & getattr(ctx["auth_data"].FLAG, "ED", 0)),
    }

    rp_id_hash_bytes = getattr(ctx["auth_data"], "rp_id_hash", b"")
    if isinstance(rp_id_hash_bytes, (bytearray, memoryview)):
        rp_id_hash_bytes = bytes(rp_id_hash_bytes)
    elif not isinstance(rp_id_hash_bytes, bytes):
        rp_id_hash_bytes = b""

    rp_id_hash_hex = rp_id_hash_bytes.hex() if rp_id_hash_bytes else ""
    rp_id_hash_b64 = (
        encode_base64url(rp_id_hash_bytes)
        if rp_id_hash_bytes
        else ""
    )

    expected_rp_hash_bytes = hashlib.sha256((ctx["resolved_rp_id"] or "").encode("utf-8")).digest()
    expected_rp_hash_hex = expected_rp_hash_bytes.hex()
    expected_rp_hash_b64 = encode_base64url(expected_rp_hash_bytes)

    if ctx["attestation_rp_id_hash_valid"] is None:
        ctx["attestation_rp_id_hash_valid"] = rp_id_hash_bytes == expected_rp_hash_bytes

    if rp_id_hash_hex:
        ctx["credential_properties"]["rpIdHash"] = rp_id_hash_hex
    if rp_id_hash_b64:
        ctx["credential_properties"]["rpIdHashBase64"] = rp_id_hash_b64
    ctx["credential_properties"]["rpIdHashExpected"] = expected_rp_hash_hex
    ctx["credential_properties"]["rpIdHashExpectedBase64"] = expected_rp_hash_b64

    ctx["authenticator_data_raw"] = authenticator_data_raw
    ctx["authenticator_data_hex"] = authenticator_data_hex
    ctx["authenticator_data_hash"] = authenticator_data_hash
    ctx["algo"] = algo
    ctx["algoname"] = algoname
    ctx["flags_value"] = flags_value
    ctx["flags_dict"] = flags_dict
    ctx["rp_id_hash_bytes"] = rp_id_hash_bytes
    ctx["rp_id_hash_hex"] = rp_id_hash_hex
    ctx["rp_id_hash_b64"] = rp_id_hash_b64
    ctx["expected_rp_hash_bytes"] = expected_rp_hash_bytes
    ctx["expected_rp_hash_hex"] = expected_rp_hash_hex
    ctx["expected_rp_hash_b64"] = expected_rp_hash_b64


def build_stored_credential_context(ctx: dict[str, Any]) -> None:
    stored_credential: dict[str, Any] = {
        "type": "simple",
        "email": ctx["uname"],
        "userName": ctx["credential_info"]["user_info"].get("name", ctx["uname"]),
        "displayName": ctx["credential_info"]["user_info"].get("display_name", ctx["uname"]),
        "credentialId": ctx["credential_id_b64"],
        "credentialIdBase64Url": ctx["credential_id_b64u"],
        "credentialIdHex": ctx["credential_id_hex"],
        "aaguid": encode_base64url(ctx["aaguid_bytes"])
        if ctx["aaguid_bytes"]
        else None,
        "aaguidHex": ctx["aaguid_bytes"].hex() if ctx["aaguid_bytes"] else None,
        "publicKey": encode_base64(ctx["public_key_bytes"]),
        "publicKeyBase64Url": encode_base64url(ctx["public_key_bytes"]),
        "publicKeyAlgorithm": ctx["credential_info"].get("publicKeyAlgorithm") or ctx["algo"],
        "signCount": getattr(ctx["auth_data"], "counter", 0),
        "createdAt": ctx["credential_info"]["registration_time"],
        "clientExtensionOutputs": credentials.convert_bytes_for_json(ctx["client_extension_results"]),
        "attestationFormat": ctx["attestation_format"],
        "attestationStatement": credentials.convert_bytes_for_json(ctx["attestation_statement"]),
        "properties": credentials.convert_bytes_for_json(ctx["credential_properties"]),
        "publicKeyCose": credentials.convert_bytes_for_json(ctx["cose_public_key"]),
        "publicKeyBytes": encode_base64(ctx["public_key_bytes"]),
        "authenticatorAttachment": ctx["authenticator_attachment_response"],
        "clientDataJSON": ctx["credential_info"].get("client_data_json"),
        "attestationObject": ctx["credential_info"].get("attestation_object"),
        "authenticatorData": ctx["authenticator_data_raw"],
        "authenticatorDataHex": ctx["authenticator_data_hex"],
        "authenticatorDataHash": ctx["authenticator_data_hash"] or None,
        "relyingParty": attestation.make_json_safe(ctx["rp_info"]),
        "registrationResponse": ctx["credential_info"].get("registration_response"),
    }

    stored_credential["userHandle"] = ctx["user_handle_b64u"]
    ctx["stored_credential"] = stored_credential


def _persist_registered_credential_entry(ctx: dict[str, Any]) -> Any | None:
    metadata_session_id = metadata.ensure_metadata_session_id()
    existing_credentials = credentials.readkey(ctx["uname"], session_id=metadata_session_id)

    credential_entry = {
        "credential_data": ctx["auth_data"].credential_data,
        "auth_data": ctx["auth_data"],
        # Advanced on every successful authentication; see authenticate.
        "sign_count": int(getattr(ctx["auth_data"], "counter", 0)),
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
        credential_entry["attestation_object_decoded"] = attestation.make_json_safe(
            ctx["parsed_attestation_object"]
        )

    if isinstance(existing_credentials, list):
        existing_credentials.append(credential_entry)
    else:
        existing_credentials = [credential_entry]

    try:
        credentials.savekey(ctx["uname"], existing_credentials, session_id=metadata_session_id)
    except Exception:
        config.app.logger.exception("Failed to persist registered credential for %s", ctx["uname"])
        return jsonify({"error": "Unable to persist registered credential."}), 500

    return None


def _update_session_simple_credentials(ctx: dict[str, Any]) -> None:
    session_simple_credentials = session.get("simple_credentials")
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
        session["simple_credentials"] = session_simple_credentials


def _record_registration_event(ctx: dict[str, Any]) -> None:
    metadata_description: str | None = None
    if isinstance(ctx["metadata_summary"], Mapping):
        raw_description = ctx["metadata_summary"].get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = ctx["response"].get("transports") if isinstance(ctx["response"], Mapping) else None
    transports: list[str] | None = None
    if isinstance(transports_field, list):
        transports = [str(item) for item in transports_field if isinstance(item, str)]

    event = device_logs.RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
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
        attestation_object=binary_helpers.decode_base64url_bytes(ctx["raw_attestation_object_b64"]),
        client_data_json=binary_helpers.decode_base64url_bytes(ctx["client_data_json_b64"]),
        signature_valid=ctx["attestation_signature_valid"],
        root_valid=ctx["attestation_root_valid"],
        rp_id_hash_valid=ctx["attestation_rp_id_hash_valid"],
        aaguid_match=ctx["attestation_aaguid_match"],
    )

    device_logs.record_registration_event(event)


def persist_registration_context(ctx: dict[str, Any]) -> Any | None:
    persist_response = _persist_registered_credential_entry(ctx)
    if persist_response is not None:
        return persist_response

    _update_session_simple_credentials(ctx)
    _record_registration_event(ctx)
    return None


def build_register_complete_response_payload(ctx: dict[str, Any]) -> dict[str, Any]:
    response_payload: dict[str, Any] = {
        "status": "OK",
        "algo": ctx["algoname"],
        **ctx["debug_info"],
        "storedCredential": credentials.convert_bytes_for_json(ctx["stored_credential"]),
        "relyingParty": ctx["rp_info"],
    }
    if ctx["warnings"]:
        response_payload["warnings"] = ctx["warnings"]
    return response_payload


def populate_rp_debug_context(ctx: dict[str, Any]) -> None:
    registration_timestamp = datetime.fromtimestamp(
        ctx["credential_info"]["registration_time"], timezone.utc
    ).isoformat()

    large_blob_result = False
    if isinstance(ctx["client_extension_results"], Mapping) and "largeBlob" in ctx["client_extension_results"]:
        large_blob_value = ctx["client_extension_results"].get("largeBlob")
        if isinstance(large_blob_value, Mapping):
            large_blob_result = bool(
                large_blob_value.get("supported")
                or large_blob_value.get("written")
                or large_blob_value.get("blob")
                or large_blob_value.get("result")
            )
        else:
            large_blob_result = bool(large_blob_value)

    credential_id_bytes = ctx["auth_data"].credential_data.credential_id
    credential_id_hex = credential_id_bytes.hex()
    credential_id_b64 = encode_base64(credential_id_bytes)
    credential_id_b64u = encode_base64url(credential_id_bytes)

    try:
        aaguid_bytes = bytes(ctx["auth_data"].credential_data.aaguid)
    except Exception:
        aaguid_bytes = b""

    cose_public_key = dict(getattr(ctx["auth_data"].credential_data, "public_key", {}))
    public_key_bytes = cbor.encode(cose_public_key)

    user_handle_value = ctx["credential_info"]["user_info"].get("user_handle")
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        user_handle_bytes = bytes(user_handle_value)
    else:
        user_handle_bytes = str(user_handle_value or "").encode("utf-8")
    user_handle_b64 = encode_base64(user_handle_bytes)
    user_handle_b64u = encode_base64url(user_handle_bytes)
    user_handle_hex = user_handle_bytes.hex()

    rp_registration_data = {
        "authenticatorData": ctx["authenticator_data_hex"],
        "authenticatorDataHash": ctx["authenticator_data_hash"],
        "clientExtensionResults": credentials.convert_bytes_for_json(ctx["client_extension_results"]),
        "flags": ctx["flags_dict"],
        "signatureCounter": getattr(ctx["auth_data"], "counter", 0),
        "attestationChecks": ctx["attestation_checks_safe"],
        "attestationSummary": ctx["attestation_summary"],
    }
    if ctx["warnings"]:
        rp_registration_data["warnings"] = ctx["warnings"]

    rp_info: dict[str, Any] = {
        "attestationFmt": ctx["attestation_format"],
        "createdAt": registration_timestamp,
        "credentialId": credential_id_hex,
        "credentialIdBase64": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64u,
        "rpIdHash": ctx["rp_id_hash_hex"],
        "rpIdHashBase64": ctx["rp_id_hash_b64"],
        "rpIdHashExpected": ctx["expected_rp_hash_hex"],
        "rpIdHashExpectedBase64": ctx["expected_rp_hash_b64"],
        "rpIdHashMatch": bool(ctx["attestation_rp_id_hash_valid"]),
        "authenticatorDataHash": ctx["authenticator_data_hash"],
        "largeBlob": large_blob_result,
        "publicKeyAlgorithm": ctx["algo"],
        "registrationData": rp_registration_data,
        "userHandle": {
            "base64": user_handle_b64,
            "base64url": user_handle_b64u,
            "hex": user_handle_hex,
        },
    }

    if aaguid_bytes:
        rp_info["aaguid"] = {
            "raw": aaguid_bytes.hex(),
            "guid": str(uuid.UUID(bytes=aaguid_bytes)) if len(aaguid_bytes) == 16 else None,
        }

    ctx["credential_info"]["relying_party"] = attestation.make_json_safe(rp_info)

    debug_info = {
        "attestationFormat": ctx["attestation_format"],
        "algorithmsUsed": [ctx["algo"]],
        "excludeCredentialsUsed": False,
        "hintsUsed": [],
        "credProtectUsed": "none",
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(ctx["flags_value"] & getattr(ctx["auth_data"].FLAG, "BE", 0)),
        "attestationSummary": ctx["attestation_summary"],
        "rpIdHashValid": ctx["attestation_rp_id_hash_valid"],
        "rpIdHash": ctx["rp_id_hash_hex"],
        "rpIdHashExpected": ctx["expected_rp_hash_hex"],
    }

    ctx["credential_id_bytes"] = credential_id_bytes
    ctx["credential_id_hex"] = credential_id_hex
    ctx["credential_id_b64"] = credential_id_b64
    ctx["credential_id_b64u"] = credential_id_b64u
    ctx["aaguid_bytes"] = aaguid_bytes
    ctx["cose_public_key"] = cose_public_key
    ctx["public_key_bytes"] = public_key_bytes
    ctx["user_handle_bytes"] = user_handle_bytes
    ctx["user_handle_b64u"] = user_handle_b64u
    ctx["rp_info"] = rp_info
    ctx["debug_info"] = debug_info


def register_complete():
    uname = request.args.get("email")
    response = request.get_json(silent=True) or {}
    credential_response = response.get("response", {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = attestation.extract_attestation_details(response)

    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = client_data_json_b64
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = attestation.extract_min_pin_length(client_extension_results)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, dict):
        response.pop("__session_state", None)

    rp_id = session.get("register_rp_id")
    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side is what makes it single-use.
    state = session.pop("state", None)
    if state is None:
        # Drop any stale ceremony leftovers so the next attempt starts clean.
        session.pop("register_rp_id", None)
        session.pop("simple_register_public_key", None)
        return (
            jsonify(
                {
                    "error": "Registration state not found or has expired. Please restart the registration process."
                }
            ),
            400,
        )

    challenge_verdict = consume_ceremony_state(state)
    if challenge_verdict != CHALLENGE_FRESH:
        session.pop("register_rp_id", None)
        session.pop("simple_register_public_key", None)
        if challenge_verdict == CHALLENGE_REPLAYED:
            message = (
                "This registration challenge has already been used. "
                "Please restart the registration process."
            )
        else:
            message = "Registration challenge has expired. Please restart the registration process."
        return jsonify({"error": message}), 400

    public_key_options_for_checks = session.pop("simple_register_public_key", None)
    resolved_rp_id = rp_id or config.determine_rp_id()
    server = config.create_fido_server(rp_id=resolved_rp_id)

    try:
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        session.pop("register_rp_id", None)
        return jsonify({"error": str(exc)}), 400

    authenticator_attachment_response = normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )

    raw_attestation_object_b64 = credential_response.get("attestationObject")
    raw_attestation_object = raw_attestation_object_b64

    # The origin the ceremony claims, read from clientDataJSON -- NOT from the
    # request's own Origin header, which the caller also controls.
    ceremony_origin = config.extract_client_data_origin(credential_response)
    if not config.is_origin_allowed(ceremony_origin):
        session.pop("register_rp_id", None)
        return (
            jsonify(
                {
                    "error": (
                        "Ceremony origin is not permitted by the configured "
                        "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                    )
                }
            ),
            400,
        )

    # determine_expected_origin only echoes a candidate that is itself
    # allowlisted, so this can never become a self-referential comparison.
    expected_origin = config.determine_expected_origin(ceremony_origin) or (
        request.host_url.rstrip("/")
    )

    attestation_checks = attestation.perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
        auth_data,
        expected_origin,
        resolved_rp_id,
    )

    ctx: dict[str, Any] = {
        "uname": uname,
        "response": response,
        "credential_response": credential_response,
        "attestation_format": attestation_format,
        "attestation_statement": attestation_statement,
        "parsed_attestation_object": parsed_attestation_object,
        "attestation_certificate_details": attestation_certificate_details,
        "attestation_certificates_details": attestation_certificates_details,
        "client_data_json_b64": client_data_json_b64,
        "client_data_json": client_data_json,
        "client_extension_results": client_extension_results,
        "min_pin_length_value": min_pin_length_value,
        "auth_data": auth_data,
        "authenticator_attachment_response": authenticator_attachment_response,
        "raw_attestation_object_b64": raw_attestation_object_b64,
        "raw_attestation_object": raw_attestation_object,
        "resolved_rp_id": resolved_rp_id,
        "attestation_signature_valid": attestation_checks.get("signature_valid"),
        "attestation_root_valid": attestation_checks.get("root_valid"),
        "attestation_rp_id_hash_valid": attestation_checks.get("rp_id_hash_valid"),
        "attestation_aaguid_match": attestation_checks.get("aaguid_match"),
        "attestation_checks_safe": attestation.make_json_safe(attestation_checks),
    }

    attestation_errors = attestation_checks.get("errors")
    if isinstance(attestation_errors, list) and attestation_errors:
        session.pop("register_rp_id", None)
        return (
            jsonify(
                {
                    "error": "Registration verification failed.",
                    "verified": False,
                    "attestationErrors": [
                        str(message) for message in attestation_errors
                    ],
                }
            ),
            400,
        )

    initialize_registration_context(ctx)
    populate_authenticator_data_context(ctx)
    populate_rp_debug_context(ctx)

    session.pop("register_rp_id", None)

    build_stored_credential_context(ctx)

    persist_response = persist_registration_context(ctx)
    if persist_response is not None:
        return persist_response

    response_payload = build_register_complete_response_payload(ctx)
    return jsonify(response_payload)


_SIMPLE_ALLOWED_ALGORITHMS: tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)

def register_begin():
    payload = request.get_json(silent=True) or {}

    existing_credentials_raw: list[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, serialized = parsing._parse_client_credentials(existing_credentials_raw)
    if serialized:
        session["simple_credentials"] = serialized
    else:
        session.pop("simple_credentials", None)

    rp_id = config.determine_rp_id()
    server = config.create_fido_server(rp_id=rp_id)

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["state"] = stamp_ceremony_state(dict(state))
    session["register_rp_id"] = rp_id

    options_dict = dict(options)
    # The ceremony state (and therefore the challenge) is deliberately NOT
    # returned to the client: the simple flow binds the challenge to the
    # server-side session only.
    public_key_options = options_dict.get("publicKey")
    if isinstance(public_key_options, MutableMapping):
        session["simple_register_public_key"] = attestation.make_json_safe(public_key_options)
    else:
        session.pop("simple_register_public_key", None)

    if _SIMPLE_ALLOWED_ALGORITHMS:
        public_key_options = options_dict.get("publicKey")
        if isinstance(public_key_options, MutableMapping):
            params = public_key_options.get("pubKeyCredParams")
            allowed_params: list[dict[str, Any]] = []
            existing_param_map: dict[int, dict[str, Any]] = {}
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, MutableMapping):
                        alg_value = param.get("alg")
                        if isinstance(alg_value, int) and alg_value in _SIMPLE_ALLOWED_ALGORITHMS:
                            cloned = dict(param)
                            cloned["type"] = "public-key"
                            existing_param_map[alg_value] = cloned
            for alg in _SIMPLE_ALLOWED_ALGORITHMS:
                if alg in existing_param_map:
                    allowed_params.append(existing_param_map[alg])
                else:
                    allowed_params.append({"type": "public-key", "alg": alg})
            public_key_options["pubKeyCredParams"] = allowed_params

    return jsonify(attestation.make_json_safe(options_dict))
