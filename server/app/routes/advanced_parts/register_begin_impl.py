from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from flask import jsonify, request, session

from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ... import attestation, config
from ...attachments import normalize_attachment, resolve_effective_attachments
from . import binary_helpers_impl
from .register_begin_support_impl import (
    build_exclude_list,
    build_processed_extensions,
    configure_allowed_algorithms,
)


def advanced_register_begin_impl(advanced_module: Any):
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
            user_id_bytes = binary_helpers_impl._extract_binary_value_impl(user_id_value)
            if isinstance(user_id_bytes, str):
                user_id_bytes = bytes.fromhex(user_id_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid user ID format: {exc}"}), 400
    else:
        user_id_bytes = username.encode("utf-8")

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = binary_helpers_impl._extract_binary_value_impl(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
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

    configure_allowed_algorithms(
        advanced_module,
        public_key,
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

    config.app.logger.info(
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

    exclude_list = build_exclude_list(advanced_module, public_key)
    processed_extensions = build_processed_extensions(advanced_module, public_key)

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
