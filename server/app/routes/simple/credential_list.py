from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from flask import jsonify, request

from ... import attestation, metadata, storage
from ...attachments import normalize_attachment
from ...encoding import encode_base64, encode_base64url


def add_registration_metadata_impl(
    target: dict[str, Any], source: Mapping[str, Any]
) -> None:
    registration_response = source.get("registration_response")
    if registration_response is None:
        registration_response = source.get("registrationResponse")
    if registration_response is not None:
        if isinstance(registration_response, Mapping):
            target["registrationResponse"] = attestation.make_json_safe(registration_response)
        else:
            target["registrationResponse"] = registration_response

    registration_rp = source.get("relying_party")
    if registration_rp is None:
        registration_rp = source.get("relyingParty")
    if registration_rp is not None:
        if isinstance(registration_rp, Mapping):
            target["relyingParty"] = attestation.make_json_safe(registration_rp)
        else:
            target["relyingParty"] = registration_rp

    client_data_value = source.get("client_data_json")
    if client_data_value is None:
        client_data_value = source.get("clientDataJSON")
    if isinstance(client_data_value, Mapping):
        target["clientDataJSON"] = attestation.make_json_safe(client_data_value)
    elif isinstance(client_data_value, str) and client_data_value:
        target["clientDataJSON"] = client_data_value


def build_credential_info_from_dict_credential_data_impl(
    email: str, cred: Mapping[str, Any]
) -> dict[str, Any]:
    cred_data = cred["credential_data"]
    auth_data = cred["auth_data"]
    user_info = cred["user_info"]

    properties_source = cred.get("properties")
    properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
    attachment_value = normalize_attachment(
        cred.get("authenticator_attachment")
        or cred.get("authenticatorAttachment")
        or properties_copy.get("authenticatorAttachment")
        or properties_copy.get("authenticator_attachment")
    )

    aaguid_hex = attestation.coerce_aaguid_hex(cred_data.get("aaguid"))

    credential_info = {
        "email": email,
        "credentialId": encode_base64(cred_data["credential_id"]),
        "userName": user_info.get("name", email),
        "displayName": user_info.get("display_name", email),
        "userHandle": encode_base64(
            user_info.get("user_handle", cred_data["credential_id"])
        )
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
        "attestationStatement": storage.convert_bytes_for_json(
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

    add_registration_metadata_impl(credential_info, cred)

    storage.add_public_key_material(credential_info, cred_data.get("public_key", {}))
    if credential_info.get("publicKeyAlgorithm") is not None:
        credential_info["algorithm"] = credential_info["publicKeyAlgorithm"]

    attestation.augment_aaguid_fields(credential_info)
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
        credential_info["attestationObjectDecoded"] = attestation.make_json_safe(decoded_attestation_value)

    raw_authenticator_value = cred.get("authenticator_data_raw") or cred.get("authenticatorDataRaw")
    authenticator_hex_value = cred.get("authenticator_data_hex") or cred.get("authenticatorDataHex")

    try:
        auth_data_bytes = bytes(auth_data)
    except Exception:
        auth_data_bytes = b""

    if auth_data_bytes:
        if not raw_authenticator_value:
            raw_authenticator_value = encode_base64url(auth_data_bytes)
        if not authenticator_hex_value:
            authenticator_hex_value = auth_data_bytes.hex()

    if raw_authenticator_value:
        credential_info["authenticatorDataRaw"] = raw_authenticator_value
    if authenticator_hex_value:
        credential_info["authenticatorDataHex"] = authenticator_hex_value

    return credential_info


def build_credential_info_from_object_credential_data_impl(
    email: str, cred: Mapping[str, Any]
) -> dict[str, Any]:
    cred_data = cred["credential_data"]
    auth_data = cred["auth_data"]
    user_info = cred["user_info"]

    properties_source = cred.get("properties")
    properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
    attachment_value = normalize_attachment(
        cred.get("authenticator_attachment")
        or cred.get("authenticatorAttachment")
        or properties_copy.get("authenticatorAttachment")
        or properties_copy.get("authenticator_attachment")
    )

    rk_from_credprops = cred.get("client_extension_outputs", {}).get("credProps", {}).get("rk", None)
    rk_from_request = cred.get("request_params", {}).get("resident_key") == "required"
    resident_key_status = rk_from_credprops if rk_from_credprops is not None else rk_from_request

    aaguid_hex = attestation.coerce_aaguid_hex(getattr(cred_data, "aaguid", None))

    credential_info = {
        "email": email,
        "credentialId": encode_base64(cred_data.credential_id),
        "userName": user_info.get("name", email),
        "displayName": user_info.get("display_name", email),
        "userHandle": encode_base64(user_info.get("user_handle"))
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
        "attestationStatement": storage.convert_bytes_for_json(
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

    add_registration_metadata_impl(credential_info, cred)

    storage.add_public_key_material(credential_info, getattr(cred_data, "public_key", {}))
    if credential_info.get("publicKeyAlgorithm") is not None:
        credential_info["algorithm"] = credential_info["publicKeyAlgorithm"]

    attestation.augment_aaguid_fields(credential_info)
    if isinstance(properties_copy, MutableMapping):
        if credential_info.get("aaguidHex"):
            properties_copy.setdefault("aaguid", credential_info["aaguidHex"])
            properties_copy.setdefault("aaguidHex", credential_info["aaguidHex"])
            properties_copy.setdefault("aaguidRaw", credential_info["aaguidHex"])
        if credential_info.get("aaguidGuid"):
            properties_copy.setdefault("aaguidGuid", credential_info["aaguidGuid"])

    return credential_info


def build_credential_info_from_bare_credential_impl(email: str, cred: Any) -> dict[str, Any]:
    aaguid_hex = attestation.coerce_aaguid_hex(getattr(cred, "aaguid", None))

    credential_info = {
        "email": email,
        "credentialId": encode_base64(cred.credential_id),
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

    storage.add_public_key_material(credential_info, getattr(cred, "public_key", {}))
    if credential_info.get("publicKeyAlgorithm") is not None:
        credential_info["algorithm"] = credential_info["publicKeyAlgorithm"]

    attestation.augment_aaguid_fields(credential_info)

    return credential_info


def list_credentials_impl():
    metadata_session_id = metadata.ensure_metadata_session_id()
    if request.method == "DELETE":
        removed = 0
        try:
            for username in list(storage.list_credentials(session_id=metadata_session_id).keys()):
                storage.delkey(username, session_id=metadata_session_id)
                removed += 1
        except Exception:
            pass

        return jsonify({"status": "OK", "removed": removed})

    credentials: list[dict[str, Any]] = []

    try:
        for email, user_creds in storage.iter_credentials(session_id=metadata_session_id):
            try:
                for cred in user_creds:
                    try:
                        if isinstance(cred, dict) and "credential_data" in cred:
                            if isinstance(cred["credential_data"], dict):
                                credential_info = build_credential_info_from_dict_credential_data_impl(email,
                                    cred,
                                )
                            else:
                                credential_info = build_credential_info_from_object_credential_data_impl(email,
                                    cred,
                                )
                        else:
                            credential_info = build_credential_info_from_bare_credential_impl(email,
                                cred,
                            )

                        credentials.append(credential_info)
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception:
        pass

    return jsonify(credentials)
