from __future__ import annotations

from typing import Any, Dict, Mapping


def populate_rp_debug_context_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    registration_timestamp = simple_module.datetime.fromtimestamp(
        ctx["credential_info"]["registration_time"], simple_module.timezone.utc
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
    credential_id_b64 = simple_module.base64.b64encode(credential_id_bytes).decode("ascii")
    credential_id_b64u = simple_module.base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")

    try:
        aaguid_bytes = bytes(ctx["auth_data"].credential_data.aaguid)
    except Exception:
        aaguid_bytes = b""

    cose_public_key = dict(getattr(ctx["auth_data"].credential_data, "public_key", {}))
    public_key_bytes = simple_module.cbor.encode(cose_public_key)

    user_handle_value = ctx["credential_info"]["user_info"].get("user_handle")
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        user_handle_bytes = bytes(user_handle_value)
    else:
        user_handle_bytes = str(user_handle_value or "").encode("utf-8")
    user_handle_b64 = simple_module.base64.b64encode(user_handle_bytes).decode("ascii")
    user_handle_b64u = simple_module.base64.urlsafe_b64encode(user_handle_bytes).decode("ascii").rstrip("=")
    user_handle_hex = user_handle_bytes.hex()

    rp_registration_data = {
        "authenticatorData": ctx["authenticator_data_hex"],
        "authenticatorDataHash": ctx["authenticator_data_hash"],
        "clientExtensionResults": simple_module.convert_bytes_for_json(ctx["client_extension_results"]),
        "flags": ctx["flags_dict"],
        "signatureCounter": getattr(ctx["auth_data"], "counter", 0),
        "attestationChecks": ctx["attestation_checks_safe"],
        "attestationSummary": ctx["attestation_summary"],
    }
    if ctx["warnings"]:
        rp_registration_data["warnings"] = ctx["warnings"]

    rp_info: Dict[str, Any] = {
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
            "guid": str(simple_module.uuid.UUID(bytes=aaguid_bytes)) if len(aaguid_bytes) == 16 else None,
        }

    ctx["credential_info"]["relying_party"] = simple_module.make_json_safe(rp_info)

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
