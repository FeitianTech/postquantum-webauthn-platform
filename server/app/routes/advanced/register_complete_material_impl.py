from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from typing import Any

from fido2 import cbor

from ... import attestation, storage
from ...encoding import encode_base64, encode_base64url
from . import logging_helpers_impl


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
    registration_timestamp = logging_helpers_impl.datetime_from_timestamp_impl(credential_info["registration_time"])

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
            "clientExtensionResults": storage.convert_bytes_for_json(client_extension_results),
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

    stored_properties = storage.convert_bytes_for_json(credential_info.get("properties", {}))
    stored_extensions = storage.convert_bytes_for_json(client_extension_results)

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
        "attestationStatement": storage.convert_bytes_for_json(attestation_statement),
        "attestationObject": storage.convert_bytes_for_json(credential_info.get("attestation_object")),
        "authenticatorData": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash,
        "clientDataJSON": storage.convert_bytes_for_json(credential_info.get("client_data_json")),
        "relyingParty": attestation.make_json_safe(rp_info),
        "properties": stored_properties,
        "registrationResponse": credential_info.get("registration_response"),
        "userHandle": user_handle_b64,
        "userHandleBase64": user_handle_b64,
        "userHandleBase64Url": user_handle_b64url,
        "userHandleHex": user_handle.hex(),
    }

    stored_credential = storage.convert_bytes_for_json(
        {k: v for k, v in stored_credential.items() if v is not None}
    )

    return {
        "storedCredential": stored_credential,
        "rpInfo": rp_info,
        "credentialIdBytes": credential_id_bytes,
        "aaguidBytes": aaguid_bytes,
    }
