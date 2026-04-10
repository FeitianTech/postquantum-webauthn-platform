from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from .credentials_builder_dict_impl import add_registration_metadata_impl


def build_credential_info_from_object_credential_data_impl(
    simple_module: Any, email: str, cred: Mapping[str, Any]
) -> Dict[str, Any]:
    cred_data = cred["credential_data"]
    auth_data = cred["auth_data"]
    user_info = cred["user_info"]

    properties_source = cred.get("properties")
    properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
    attachment_value = simple_module.normalize_attachment(
        cred.get("authenticator_attachment")
        or cred.get("authenticatorAttachment")
        or properties_copy.get("authenticatorAttachment")
        or properties_copy.get("authenticator_attachment")
    )

    rk_from_credprops = cred.get("client_extension_outputs", {}).get("credProps", {}).get("rk", None)
    rk_from_request = cred.get("request_params", {}).get("resident_key") == "required"
    resident_key_status = rk_from_credprops if rk_from_credprops is not None else rk_from_request

    aaguid_hex = simple_module.coerce_aaguid_hex(getattr(cred_data, "aaguid", None))

    credential_info = {
        "email": email,
        "credentialId": simple_module.base64.b64encode(cred_data.credential_id).decode("utf-8"),
        "userName": user_info.get("name", email),
        "displayName": user_info.get("display_name", email),
        "userHandle": simple_module.base64.b64encode(user_info.get("user_handle")).decode("utf-8")
        if user_info.get("user_handle")
        else None,
        "algorithm": cred_data.public_key[3]
        if hasattr(cred_data, "public_key") and len(cred_data.public_key) > 3
        else "Unknown",
        "type": "WebAuthn",
        "createdAt": cred.get("registration_time"),
        "signCount": auth_data.counter if hasattr(auth_data, "counter") else 0,
        "aaguid": aaguid_hex,
        "flags": {
            "up": bool(auth_data.flags & auth_data.FLAG.UP) if hasattr(auth_data, "flags") else True,
            "uv": bool(auth_data.flags & auth_data.FLAG.UV) if hasattr(auth_data, "flags") else True,
            "at": bool(auth_data.flags & auth_data.FLAG.AT) if hasattr(auth_data, "flags") else True,
            "ed": bool(auth_data.flags & auth_data.FLAG.ED) if hasattr(auth_data, "flags") else False,
            "be": bool(auth_data.flags & auth_data.FLAG.BE) if hasattr(auth_data, "flags") else False,
            "bs": bool(auth_data.flags & auth_data.FLAG.BS) if hasattr(auth_data, "flags") else False,
        },
        "clientExtensionOutputs": cred.get("client_extension_outputs", {}),
        "attestationFormat": cred.get("attestation_format", "none"),
        "attestationStatement": simple_module.convert_bytes_for_json(
            cred.get("attestation_statement", {})
        ),
        "publicKeyAlgorithm": cred_data.public_key[3]
        if hasattr(cred_data, "public_key") and len(cred_data.public_key) > 3
        else None,
        "authenticatorAttachment": attachment_value,
        "residentKey": resident_key_status,
        "largeBlob": cred.get("client_extension_outputs", {})
        .get("largeBlob", {})
        .get("supported", False),
        "requestParams": cred.get("request_params", {}),
        "properties": properties_copy,
    }

    certificate_details = cred.get("attestation_certificate")
    if certificate_details is not None:
        credential_info["attestationCertificate"] = certificate_details

    if attachment_value is not None:
        properties_copy["authenticatorAttachment"] = attachment_value

    add_registration_metadata_impl(simple_module, credential_info, cred)

    simple_module.add_public_key_material(credential_info, getattr(cred_data, "public_key", {}))
    if credential_info.get("publicKeyAlgorithm") is not None:
        credential_info["algorithm"] = credential_info["publicKeyAlgorithm"]

    simple_module.augment_aaguid_fields(credential_info)
    if isinstance(properties_copy, MutableMapping):
        if credential_info.get("aaguidHex"):
            properties_copy.setdefault("aaguid", credential_info["aaguidHex"])
            properties_copy.setdefault("aaguidHex", credential_info["aaguidHex"])
            properties_copy.setdefault("aaguidRaw", credential_info["aaguidHex"])
        if credential_info.get("aaguidGuid"):
            properties_copy.setdefault("aaguidGuid", credential_info["aaguidGuid"])

    return credential_info


def build_credential_info_from_bare_credential_impl(simple_module: Any, email: str, cred: Any) -> Dict[str, Any]:
    aaguid_hex = simple_module.coerce_aaguid_hex(getattr(cred, "aaguid", None))

    credential_info = {
        "email": email,
        "credentialId": simple_module.base64.b64encode(cred.credential_id).decode("utf-8"),
        "userName": email,
        "displayName": email,
        "userHandle": None,
        "algorithm": cred.public_key[3]
        if hasattr(cred, "public_key") and len(cred.public_key) > 3
        else "Unknown",
        "type": "WebAuthn",
        "createdAt": None,
        "signCount": 0,
        "authenticatorAttachment": None,
        "aaguid": aaguid_hex,
        "flags": {
            "up": True,
            "uv": True,
            "at": True,
            "ed": False,
            "be": False,
            "bs": False,
        },
        "clientExtensionOutputs": {},
        "attestationFormat": "none",
        "attestationStatement": {},
        "publicKeyAlgorithm": cred.public_key[3]
        if hasattr(cred, "public_key") and len(cred.public_key) > 3
        else None,
        "residentKey": False,
        "largeBlob": False,
        "properties": {},
    }

    simple_module.add_public_key_material(credential_info, getattr(cred, "public_key", {}))
    if credential_info.get("publicKeyAlgorithm") is not None:
        credential_info["algorithm"] = credential_info["publicKeyAlgorithm"]

    simple_module.augment_aaguid_fields(credential_info)

    return credential_info
