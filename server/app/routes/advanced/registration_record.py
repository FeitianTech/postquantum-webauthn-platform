"""Advanced registration complete: the record of a verified registration.

``build_credential_info`` gathers what the registration produced,
``resolve_algorithm`` and ``build_debug_info`` add the algorithm and the debug
view, and ``build_registration_material`` derives the relying-party view and the
stored credential the browser keeps. The stored credential is persisted as
JSON without sorting, so the order these add keys in is part of the output.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Mapping
from typing import Any

from fido2 import cbor

from ...encoding import encode_base64, encode_base64url
from ...storage import credentials
from ...webauthn import attestation, pqc
from . import algorithms, binary, tracing

_CRED_PROTECT_NAMES = {
    1: "userVerificationOptional",
    2: "userVerificationOptionalWithCredentialIDList",
    3: "userVerificationRequired",
}


def resolve_user_handle(user_info: Mapping[str, Any], username: str) -> Any:
    """``user.id`` decoded, or the user name's bytes when it is missing or undecodable."""

    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            return binary._decode_request_binary(user_id_value)
        except (ValueError, TypeError):
            return username.encode("utf-8")
    return username.encode("utf-8")


def build_credential_info(
    *,
    prepared: Mapping[str, Any],
    auth_data: Any,
    analysis: Mapping[str, Any],
    user_handle: Any,
    extensions_summary: Mapping[str, Any],
) -> dict[str, Any]:
    public_key = prepared["publicKey"]
    client_extension_results = prepared["clientExtensionResults"]
    attestation_certificates_details = prepared["attestationCertificatesDetails"]
    attestation_certificate_details = prepared["attestationCertificateDetails"]
    authenticator_attachment_response = prepared["authenticatorAttachmentResponse"]

    credential_info = {
        "credential_data": auth_data.credential_data,
        "auth_data": auth_data,
        "user_info": {
            "name": prepared["username"],
            "display_name": prepared["displayName"],
            "user_handle": user_handle,
        },
        "registration_time": time.time(),
        "client_data_json": prepared["clientDataJson"] or "",
        "attestation_object": prepared["rawAttestationObject"] or "",
        "attestation_format": prepared["attestationFormat"],
        "attestation_statement": prepared["attestationStatement"],
        "attestation_certificates": attestation_certificates_details,
        "client_extension_outputs": client_extension_results,
        "authenticator_attachment": authenticator_attachment_response,
        "original_webauthn_request": prepared["originalRequest"],
        "properties": {
            "excludeCredentialsSentCount": len(public_key.get("excludeCredentials", [])),
            "excludeCredentialsUsed": False,
            "credentialIdLength": len(auth_data.credential_data.credential_id),
            "fakeCredentialIdLengthRequested": None,
            "hintsSent": public_key.get("hints", []),
            "resolvedAuthenticatorAttachments": prepared["allowedAttachments"],
            "authenticatorAttachment": authenticator_attachment_response,
            "largeBlobRequested": public_key.get("extensions", {}).get("largeBlob", {}),
            "largeBlobClientOutput": client_extension_results.get("largeBlob", {}),
            "residentKeyRequested": prepared["residentKeyRequested"],
            "residentKeyRequired": bool(prepared["residentKeyRequired"]),
            "attestationSignatureValid": analysis["signatureValid"],
            "attestationRootValid": analysis["rootValid"],
            "attestationRpIdHashValid": analysis["rpIdHashValid"],
            "attestationAaguidMatch": analysis["aaguidMatch"],
            "attestationChecks": analysis["checksSafe"],
            "attestationSummary": analysis["summary"],
        },
    }

    if prepared["minPinLengthValue"] is not None:
        credential_info["properties"]["minPinLength"] = prepared["minPinLengthValue"]
    if attestation_certificates_details:
        credential_info["attestationCertificates"] = attestation_certificates_details
        credential_info["properties"]["attestationCertificates"] = attestation_certificates_details

    credentials.add_public_key_material(credential_info, getattr(auth_data.credential_data, "public_key", {}))
    attestation.augment_aaguid_fields(credential_info)
    if extensions_summary:
        credential_info["authenticator_extensions"] = extensions_summary
    if attestation_certificate_details is not None:
        credential_info["attestation_certificate"] = attestation_certificate_details
    if isinstance(prepared["response"], Mapping):
        credential_info["registration_response"] = attestation.make_json_safe(prepared["response"])
    return credential_info


def resolve_algorithm(credential_info: dict[str, Any], auth_data: Any) -> tuple[Any, str]:
    """The credential key's COSE algorithm and its name; records it in ``credential_info``."""

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
    return algo, algoname


def _cred_protect_used(extensions_requested: Mapping[str, Any]) -> Any:
    cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
    if cred_protect_requested is None:
        cred_protect_requested = extensions_requested.get("credProtect")
    if isinstance(cred_protect_requested, int):
        return _CRED_PROTECT_NAMES.get(cred_protect_requested, cred_protect_requested)
    if cred_protect_requested:
        return cred_protect_requested
    return "none"


def build_debug_info(
    *,
    public_key: Mapping[str, Any],
    attestation_format: Any,
    auth_data: Any,
    analysis: Mapping[str, Any],
    algo: Any,
    challenge_source: Any,
) -> dict[str, Any]:
    pub_key_params = public_key.get("pubKeyCredParams", [])
    algorithms_used = [param.get("alg") for param in pub_key_params if isinstance(param, dict) and "alg" in param]
    debug_info = {
        "attestationFormat": attestation_format,
        "algorithmsUsed": algorithms_used or ([algo] if algo is not None else []),
        "excludeCredentialsUsed": bool(public_key.get("excludeCredentials")),
        "hintsUsed": public_key.get("hints", []),
        "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, "flags") else False,
        "attestationSignatureValid": analysis["signatureValid"],
        "attestationRootValid": analysis["rootValid"],
        "attestationRpIdHashValid": analysis["rpIdHashValid"],
        "attestationAaguidMatch": analysis["aaguidMatch"],
        "attestationChecks": analysis["checksSafe"],
        "attestationSummary": analysis["summary"],
        "attestationErrors": analysis["errors"],
        "attestationVerified": not analysis["errors"],
        "challengeSource": challenge_source,
    }

    extensions_requested = public_key.get("extensions", {})
    if not isinstance(extensions_requested, dict):
        extensions_requested = {}
    debug_info["credProtectUsed"] = _cred_protect_used(extensions_requested)

    enforce_requested = extensions_requested.get("enforceCredentialProtectionPolicy")
    if enforce_requested is None:
        enforce_requested = extensions_requested.get("enforceCredProtect")
    debug_info["enforceCredProtectUsed"] = bool(enforce_requested)
    return debug_info


def _aaguid_values(credential_data: Any) -> tuple[bytes | None, str | None, str | None]:
    """The AAGUID's bytes, hex and GUID spelling; hex and GUID only for 16 bytes."""

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
    return aaguid_bytes, aaguid_hex, aaguid_guid


def _flags(auth_data: Any) -> dict[str, bool]:
    return {
        "AT": bool(auth_data.flags & auth_data.FLAG.AT),
        "BE": bool(auth_data.flags & auth_data.FLAG.BE),
        "BS": bool(auth_data.flags & auth_data.FLAG.BS),
        "ED": bool(auth_data.flags & auth_data.FLAG.ED),
        "UP": bool(auth_data.flags & auth_data.FLAG.UP),
        "UV": bool(auth_data.flags & auth_data.FLAG.UV),
    }


def _rp_id_hash_report(auth_data: Any, resolved_rp_id: str) -> dict[str, Any]:
    """authData's rpIdHash and the hash of the RP ID it should be, as bytes, hex and base64url."""

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
    return {
        "bytes": rp_id_hash_bytes,
        "hex": rp_id_hash_hex,
        "base64url": rp_id_hash_b64,
        "expectedBytes": expected_rp_hash_bytes,
        "expectedHex": expected_rp_hash_bytes.hex(),
        "expectedBase64url": encode_base64url(expected_rp_hash_bytes),
    }


def _resident_key_result(client_extension_results: Any, auth_data: Any, resident_key_required: bool) -> bool:
    """credProps' ``rk`` when reported, else the BE flag or the requirement."""

    cred_props = (
        client_extension_results.get("credProps") if isinstance(client_extension_results, dict) else None
    )
    if isinstance(cred_props, dict) and "rk" in cred_props:
        return bool(cred_props.get("rk"))
    if isinstance(cred_props, bool):
        return bool(cred_props)
    return bool(auth_data.flags & auth_data.FLAG.BE) or bool(resident_key_required)


def _large_blob_result(client_extension_results: Any) -> bool:
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
    return large_blob_result


def _public_key_encodings(auth_data: Any) -> tuple[str | None, str | None]:
    credential_public_key = getattr(auth_data.credential_data, "public_key", None)
    if isinstance(credential_public_key, Mapping):
        try:
            public_key_cbor_bytes = cbor.encode(dict(credential_public_key))
        except Exception:
            public_key_cbor_bytes = None
        if public_key_cbor_bytes:
            return encode_base64(public_key_cbor_bytes), encode_base64url(public_key_cbor_bytes)
    return None, None


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
    properties = credential_info["properties"]
    credential_data = auth_data.credential_data
    credential_id_bytes = getattr(credential_data, "credential_id", b"") or b""
    credential_id_hex = credential_id_bytes.hex() if credential_id_bytes else None
    credential_id_b64 = encode_base64(credential_id_bytes) if credential_id_bytes else None
    credential_id_b64url = encode_base64url(credential_id_bytes) if credential_id_bytes else None

    aaguid_bytes, aaguid_hex, aaguid_guid = _aaguid_values(credential_data)
    if aaguid_hex:
        properties["aaguid"] = aaguid_hex
        properties["aaguidHex"] = aaguid_hex
    if aaguid_guid:
        properties["aaguidGuid"] = aaguid_guid

    flags_dict = _flags(auth_data)

    auth_data_bytes = bytes(auth_data)
    authenticator_data_hex = auth_data_bytes.hex()
    authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
    registration_timestamp = tracing.datetime_from_timestamp(credential_info["registration_time"])

    rp_hash = _rp_id_hash_report(auth_data, resolved_rp_id)
    if attestation_rp_id_hash_valid is None:
        attestation_rp_id_hash_valid = rp_hash["bytes"] == rp_hash["expectedBytes"]
    if rp_hash["hex"]:
        properties["rpIdHash"] = rp_hash["hex"]
    if rp_hash["base64url"]:
        properties["rpIdHashBase64"] = rp_hash["base64url"]
    properties["rpIdHashExpected"] = rp_hash["expectedHex"]
    properties["rpIdHashExpectedBase64"] = rp_hash["expectedBase64url"]

    resident_key_result = _resident_key_result(client_extension_results, auth_data, resident_key_required)
    properties["residentKey"] = bool(resident_key_result)
    credential_info["resident_key"] = bool(resident_key_result)
    properties["authenticatorDataHash"] = authenticator_data_hash

    large_blob_result = _large_blob_result(client_extension_results)

    rp_info = {
        "aaguid": {"raw": aaguid_hex, "guid": aaguid_guid},
        "attestationFmt": attestation_format,
        "attestationObject": credential_info.get("attestation_object"),
        "createdAt": registration_timestamp,
        "credentialId": credential_id_hex,
        "credentialIdBase64": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64url,
        "rpIdHash": rp_hash["hex"],
        "rpIdHashBase64": rp_hash["base64url"],
        "rpIdHashExpected": rp_hash["expectedHex"],
        "rpIdHashExpectedBase64": rp_hash["expectedBase64url"],
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

    stored_credential = _stored_credential(
        credential_info=credential_info,
        auth_data=auth_data,
        attestation_format=attestation_format,
        attestation_statement=attestation_statement,
        client_extension_results=client_extension_results,
        rp_info=rp_info,
        user_handle=user_handle,
        identifiers=(credential_id_b64, credential_id_b64url, credential_id_hex),
        aaguid=(aaguid_bytes, aaguid_hex, aaguid_guid),
        resident_key_result=resident_key_result,
        large_blob_result=large_blob_result,
        authenticator_data=(authenticator_data_hex, authenticator_data_hash),
    )

    return {
        "storedCredential": stored_credential,
        "rpInfo": rp_info,
        "credentialIdBytes": credential_id_bytes,
        "aaguidBytes": aaguid_bytes,
    }


def _stored_credential(
    *,
    credential_info: Mapping[str, Any],
    auth_data: Any,
    attestation_format: Any,
    attestation_statement: Any,
    client_extension_results: Any,
    rp_info: Mapping[str, Any],
    user_handle: bytes,
    identifiers: tuple[Any, Any, Any],
    aaguid: tuple[Any, Any, Any],
    resident_key_result: bool,
    large_blob_result: bool,
    authenticator_data: tuple[str, str],
) -> dict[str, Any]:
    """The credential record the browser keeps (and the artifact store persists)."""

    credential_id_b64, credential_id_b64url, credential_id_hex = identifiers
    aaguid_bytes, aaguid_hex, aaguid_guid = aaguid
    authenticator_data_hex, authenticator_data_hash = authenticator_data

    user_handle_b64url = encode_base64url(user_handle)
    user_handle_b64 = encode_base64(user_handle)

    stored_properties = credentials.convert_bytes_for_json(credential_info.get("properties", {}))
    stored_extensions = credentials.convert_bytes_for_json(client_extension_results)
    public_key_b64, public_key_b64url = _public_key_encodings(auth_data)

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

    return credentials.convert_bytes_for_json(
        {k: v for k, v in stored_credential.items() if v is not None}
    )
