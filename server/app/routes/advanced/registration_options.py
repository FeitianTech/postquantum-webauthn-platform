"""Advanced registration begin: the request's checks and the options fido2 is given.

``advanced_register_begin`` in :mod:`.registration` runs these in order: the
request's required fields, the server for its RP, the authenticator selection
and the excluded credentials and extensions.
"""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any, NamedTuple

from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from flask import jsonify

from ...config import relying_party
from ...webauthn import client_binary
from ...webauthn.attachments import (
    normalize_attachment,
    request_hints,
    resolve_effective_attachments,
)
from ...webauthn.attestation.aaguid import describe_cred_protect


class BeginRequest(NamedTuple):
    public_key: Any
    username: str
    display_name: str
    user_id: bytes
    challenge: bytes | None


class AuthenticatorSelection(NamedTuple):
    allowed_attachments: list[str]
    user_verification: UserVerificationRequirement
    attachment: AuthenticatorAttachment | None
    resident_key: ResidentKeyRequirement


def parse_begin_request(data: Any) -> tuple[BeginRequest | None, Any]:
    """The user, user id and challenge a register-begin request names, or the 400 it earns."""

    if not data or not data.get("publicKey"):
        return None, (
            jsonify({"error": "Invalid request: Missing publicKey in CredentialCreationOptions"}),
            400,
        )

    public_key = data["publicKey"]

    if not public_key.get("rp"):
        return None, (jsonify({"error": "Missing required field: rp"}), 400)
    if not public_key.get("user"):
        return None, (jsonify({"error": "Missing required field: user"}), 400)
    if not public_key.get("challenge"):
        return None, (jsonify({"error": "Missing required field: challenge"}), 400)

    user_info = public_key["user"]
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)

    if not username:
        return None, (jsonify({"error": "Username is required in user.name"}), 400)

    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            user_id_bytes = client_binary.read_request_field(user_id_value)
        except (ValueError, TypeError) as exc:
            return None, (jsonify({"error": f"Invalid user ID format: {exc}"}), 400)
    else:
        user_id_bytes = username.encode("utf-8")

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = client_binary.read_request_field(challenge_value)
        except (ValueError, TypeError) as exc:
            return None, (jsonify({"error": f"Invalid challenge format: {exc}"}), 400)

    return BeginRequest(public_key, username, display_name, user_id_bytes, challenge_bytes), None


def registration_server(public_key: Any) -> tuple[Any, Any]:
    """A fido2 server for the request's RP, sanitised into ``public_key``, and that RP."""

    rp_input = public_key.get("rp") if isinstance(public_key, Mapping) else None
    rp_entity = relying_party.build_rp_entity(rp_input)
    sanitized_rp = {"id": rp_entity.id, "name": rp_entity.name}
    if isinstance(rp_input, Mapping):
        sanitized_rp.update({k: v for k, v in rp_input.items() if k not in {"id", "name"}})
    if isinstance(public_key, MutableMapping):
        public_key["rp"] = sanitized_rp

    temp_server = relying_party.create_fido_server(rp_data=sanitized_rp)

    # In milliseconds, as the options carry it (fido2 passes the server's timeout through).
    temp_server.timeout = public_key.get("timeout", 90000) or None

    # fido2's string enums answer None for a value they do not know.
    temp_server.attestation = (
        AttestationConveyancePreference(public_key.get("attestation", "none"))
        or AttestationConveyancePreference.NONE
    )

    return temp_server, rp_entity


def authenticator_selection(public_key: Any) -> AuthenticatorSelection:
    """The attachments the hints allow, and the UV, attachment and resident-key requirements."""

    auth_selection = public_key.get("authenticatorSelection", {})
    if not isinstance(auth_selection, dict):
        auth_selection = {}
        public_key["authenticatorSelection"] = auth_selection

    requested_attachment = normalize_attachment(
        auth_selection.get("authenticatorAttachment")
    )
    allowed_attachment_values = resolve_effective_attachments(
        request_hints(public_key),
        requested_attachment,
    )

    uv_req = (
        UserVerificationRequirement(auth_selection.get("userVerification", "preferred"))
        or UserVerificationRequirement.PREFERRED
    )

    attachment_source = requested_attachment
    if not attachment_source and len(allowed_attachment_values) == 1:
        attachment_source = allowed_attachment_values[0]
    auth_attachment = AuthenticatorAttachment(attachment_source) if attachment_source else None

    if auth_selection.get("requireResidentKey") is True:
        rk_req = ResidentKeyRequirement.REQUIRED
    else:
        rk_req = (
            ResidentKeyRequirement(auth_selection.get("residentKey", "preferred"))
            or ResidentKeyRequirement.PREFERRED
        )

    return AuthenticatorSelection(allowed_attachment_values, uv_req, auth_attachment, rk_req)


def build_exclude_list(public_key: Mapping[str, Any]) -> list[Any]:
    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = client_binary.read_request_field(exclude_cred.get("id", ""))
                if cred_id:
                    exclude_list.append(
                        PublicKeyCredentialDescriptor(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            id=cred_id,
                        )
                    )
    return exclude_list


def _prf_extension(value: Any) -> Any:
    if not (isinstance(value, dict) and "eval" in value):
        return value
    prf_eval = value["eval"]
    processed_eval = {}
    if isinstance(prf_eval, dict):
        if "first" in prf_eval:
            processed_eval["first"] = client_binary.read_request_field(prf_eval["first"])
        if "second" in prf_eval:
            processed_eval["second"] = client_binary.read_request_field(prf_eval["second"])
    return {"eval": processed_eval} if processed_eval else value


def build_processed_extensions(public_key: Mapping[str, Any]) -> dict[str, Any]:
    extensions = public_key.get("extensions", {})
    processed_extensions: dict[str, Any] = {}

    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            processed_extensions["credentialProtectionPolicy"] = describe_cred_protect(ext_value)
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredentialProtectionPolicy"] = bool(ext_value)
        elif ext_name == "largeBlob":
            processed_extensions["largeBlob"] = {"support": ext_value} if isinstance(ext_value, str) else ext_value
        elif ext_name == "prf":
            processed_extensions["prf"] = _prf_extension(ext_value)
        else:
            processed_extensions[ext_name] = ext_value

    return processed_extensions
