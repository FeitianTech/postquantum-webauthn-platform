from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping


def add_registration_metadata_impl(
    simple_module: Any, target: Dict[str, Any], source: Mapping[str, Any]
) -> None:
    registration_response = source.get("registration_response")
    if registration_response is None:
        registration_response = source.get("registrationResponse")
    if registration_response is not None:
        if isinstance(registration_response, Mapping):
            target["registrationResponse"] = simple_module.make_json_safe(registration_response)
        else:
            target["registrationResponse"] = registration_response

    registration_rp = source.get("relying_party")
    if registration_rp is None:
        registration_rp = source.get("relyingParty")
    if registration_rp is not None:
        if isinstance(registration_rp, Mapping):
            target["relyingParty"] = simple_module.make_json_safe(registration_rp)
        else:
            target["relyingParty"] = registration_rp

    client_data_value = source.get("client_data_json")
    if client_data_value is None:
        client_data_value = source.get("clientDataJSON")
    if isinstance(client_data_value, Mapping):
        target["clientDataJSON"] = simple_module.make_json_safe(client_data_value)
    elif isinstance(client_data_value, str) and client_data_value:
        target["clientDataJSON"] = client_data_value


def build_credential_info_from_dict_credential_data_impl(
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

    aaguid_hex = simple_module.coerce_aaguid_hex(cred_data.get("aaguid"))

    credential_info = {
        "email": email,
        "credentialId": simple_module.base64.b64encode(cred_data["credential_id"]).decode("utf-8"),
        "userName": user_info.get("name", email),
        "displayName": user_info.get("display_name", email),
        "userHandle": simple_module.base64.b64encode(
            user_info.get("user_handle", cred_data["credential_id"])
        ).decode("utf-8")
        if user_info.get("user_handle")
        else None,
        "algorithm": cred_data.get("public_key", {}).get(3, "Unknown"),
        "type": "WebAuthn",
        "createdAt": cred.get("registration_time"),
        "signCount": auth_data.get("counter", 0),
        "aaguid": aaguid_hex,
        "flags": auth_data.get("flags", {}),
        "clientExtensionOutputs": cred.get("client_extension_outputs", {}),
        "attestationFormat": cred.get("attestation_format", "none"),
        "attestationStatement": simple_module.convert_bytes_for_json(
            cred.get("attestation_statement", {})
        ),
        "publicKeyAlgorithm": cred_data.get("public_key", {}).get(3),
        "authenticatorAttachment": attachment_value,
        "residentKey": auth_data.get("flags", {}).get("be", False),
        "largeBlob": cred.get("client_extension_outputs", {})
        .get("largeBlob", {})
        .get("supported", False),
        "properties": properties_copy,
    }

    if attachment_value is not None:
        properties_copy["authenticatorAttachment"] = attachment_value

    certificate_details = cred.get("attestation_certificate")
    if certificate_details is not None:
        credential_info["attestationCertificate"] = certificate_details

    certificates_list = cred.get("attestation_certificates") or cred.get("attestationCertificates")
    if certificates_list:
        credential_info["attestationCertificates"] = certificates_list
        credential_info["attestation_certificates"] = certificates_list

    add_registration_metadata_impl(simple_module, credential_info, cred)

    simple_module.add_public_key_material(credential_info, cred_data.get("public_key", {}))
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

    raw_attestation_value = cred.get("attestation_object_raw") or cred.get("attestationObjectRaw")
    if not raw_attestation_value:
        stored_att_obj = cred.get("attestation_object")
        if isinstance(stored_att_obj, str):
            raw_attestation_value = stored_att_obj

    decoded_attestation_value = cred.get("attestation_object_decoded") or cred.get(
        "attestationObjectDecoded"
    )
    if decoded_attestation_value is None:
        stored_att_obj = cred.get("attestation_object")
        if isinstance(stored_att_obj, Mapping):
            decoded_attestation_value = stored_att_obj

    if raw_attestation_value:
        credential_info["attestationObjectRaw"] = raw_attestation_value
    if decoded_attestation_value is not None:
        credential_info["attestationObjectDecoded"] = simple_module.make_json_safe(decoded_attestation_value)

    raw_authenticator_value = cred.get("authenticator_data_raw") or cred.get("authenticatorDataRaw")
    authenticator_hex_value = cred.get("authenticator_data_hex") or cred.get("authenticatorDataHex")

    try:
        auth_data_bytes = bytes(auth_data)
    except Exception:
        auth_data_bytes = b""

    if auth_data_bytes:
        if not raw_authenticator_value:
            raw_authenticator_value = simple_module.base64.urlsafe_b64encode(auth_data_bytes).decode(
                "utf-8"
            ).rstrip("=")
        if not authenticator_hex_value:
            authenticator_hex_value = auth_data_bytes.hex()

    if raw_authenticator_value:
        credential_info["authenticatorDataRaw"] = raw_authenticator_value
    if authenticator_hex_value:
        credential_info["authenticatorDataHex"] = authenticator_hex_value

    return credential_info
