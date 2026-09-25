"""Simple registration complete: the record of a verified registration.

Each step reads and extends one ``ctx`` dict: the attestation summary and the
credential's info and properties, the authenticator data, the relying-party
and debug views, then the credential the browser keeps. The stored record is
JSON, so the order these add keys in is part of the output.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fido2 import cbor

from ...encoding import encode_base64, encode_base64url
from ...storage import credentials
from ...webauthn import attestation

# What the registration answer calls the credential's algorithm. Compared with
# ``==`` rather than looked up: a crafted COSE key's alg need not be hashable.
_ALGORITHM_NAMES = (
    (-50, "ML-DSA-87 (PQC)"),
    (-49, "ML-DSA-65 (PQC)"),
    (-48, "ML-DSA-44 (PQC)"),
    (-7, "ES256 (ECDSA)"),
    (-257, "RS256 (RSA)"),
)


def _attestation_summary(ctx: Mapping[str, Any]) -> tuple[dict[str, Any], Any, list[str]]:
    """The attestation summary, the metadata summary, and the attestation warnings as text."""

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
    return attestation_summary, metadata_summary, warnings


def _credential_info(ctx: Mapping[str, Any]) -> dict[str, Any]:
    return {
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


def _record_aaguid(credential_properties: dict[str, Any], credential_data: Any) -> None:
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


def initialize_registration_context(ctx: dict[str, Any]) -> None:
    attestation_summary, metadata_summary, warnings = _attestation_summary(ctx)
    credential_info = _credential_info(ctx)

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

    _record_aaguid(credential_properties, ctx["auth_data"].credential_data)

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
    algoname = next((name for alg, name in _ALGORITHM_NAMES if algo == alg), "Other (Classical)")

    flags_value = getattr(ctx["auth_data"], "flags", 0)
    flags_dict = {
        flag: bool(flags_value & getattr(ctx["auth_data"].FLAG, flag, 0))
        for flag in ("UP", "UV", "BE", "BS", "AT", "ED")
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


def _large_blob_result(client_extension_results: Any) -> bool:
    large_blob_result = False
    if isinstance(client_extension_results, Mapping) and "largeBlob" in client_extension_results:
        large_blob_value = client_extension_results.get("largeBlob")
        if isinstance(large_blob_value, Mapping):
            large_blob_result = bool(
                large_blob_value.get("supported")
                or large_blob_value.get("written")
                or large_blob_value.get("blob")
                or large_blob_value.get("result")
            )
        else:
            large_blob_result = bool(large_blob_value)
    return large_blob_result


def _user_handle_bytes(user_info: Mapping[str, Any]) -> bytes:
    user_handle_value = user_info.get("user_handle")
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        return bytes(user_handle_value)
    return str(user_handle_value or "").encode("utf-8")


def _relying_party_info(
    ctx: Mapping[str, Any],
    *,
    registration_timestamp: str,
    credential_ids: tuple[str, str, str],
    aaguid_bytes: bytes,
    large_blob_result: bool,
    user_handle_bytes: bytes,
) -> dict[str, Any]:
    """The relying party's view of the registration, as the answer reports it."""

    credential_id_hex, credential_id_b64, credential_id_b64u = credential_ids
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
            "base64": encode_base64(user_handle_bytes),
            "base64url": encode_base64url(user_handle_bytes),
            "hex": user_handle_bytes.hex(),
        },
    }

    if aaguid_bytes:
        rp_info["aaguid"] = {
            "raw": aaguid_bytes.hex(),
            "guid": str(uuid.UUID(bytes=aaguid_bytes)) if len(aaguid_bytes) == 16 else None,
        }
    return rp_info


def _debug_info(ctx: Mapping[str, Any]) -> dict[str, Any]:
    return {
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


def populate_rp_debug_context(ctx: dict[str, Any]) -> None:
    registration_timestamp = datetime.fromtimestamp(
        ctx["credential_info"]["registration_time"], timezone.utc
    ).isoformat()
    large_blob_result = _large_blob_result(ctx["client_extension_results"])

    credential_id_bytes = ctx["auth_data"].credential_data.credential_id
    credential_ids = (
        credential_id_bytes.hex(),
        encode_base64(credential_id_bytes),
        encode_base64url(credential_id_bytes),
    )

    try:
        aaguid_bytes = bytes(ctx["auth_data"].credential_data.aaguid)
    except Exception:
        aaguid_bytes = b""

    cose_public_key = dict(getattr(ctx["auth_data"].credential_data, "public_key", {}))
    public_key_bytes = cbor.encode(cose_public_key)
    user_handle_bytes = _user_handle_bytes(ctx["credential_info"]["user_info"])

    rp_info = _relying_party_info(
        ctx,
        registration_timestamp=registration_timestamp,
        credential_ids=credential_ids,
        aaguid_bytes=aaguid_bytes,
        large_blob_result=large_blob_result,
        user_handle_bytes=user_handle_bytes,
    )
    ctx["credential_info"]["relying_party"] = attestation.make_json_safe(rp_info)
    debug_info = _debug_info(ctx)

    ctx["credential_id_bytes"] = credential_id_bytes
    ctx["credential_id_hex"], ctx["credential_id_b64"], ctx["credential_id_b64u"] = credential_ids
    ctx["aaguid_bytes"] = aaguid_bytes
    ctx["cose_public_key"] = cose_public_key
    ctx["public_key_bytes"] = public_key_bytes
    ctx["user_handle_bytes"] = user_handle_bytes
    ctx["user_handle_b64u"] = encode_base64url(user_handle_bytes)
    ctx["rp_info"] = rp_info
    ctx["debug_info"] = debug_info


def build_stored_credential_context(ctx: dict[str, Any]) -> None:
    stored_credential: dict[str, Any] = {
        "type": "simple",
        "email": ctx["uname"],
        "userName": ctx["credential_info"]["user_info"].get("name", ctx["uname"]),
        "displayName": ctx["credential_info"]["user_info"].get("display_name", ctx["uname"]),
        "credentialId": ctx["credential_id_b64u"],
        "credentialIdBase64Url": ctx["credential_id_b64u"],
        "credentialIdHex": ctx["credential_id_hex"],
        "aaguid": encode_base64url(ctx["aaguid_bytes"])
        if ctx["aaguid_bytes"]
        else None,
        "aaguidHex": ctx["aaguid_bytes"].hex() if ctx["aaguid_bytes"] else None,
        "publicKey": encode_base64url(ctx["public_key_bytes"]),
        "publicKeyBase64Url": encode_base64url(ctx["public_key_bytes"]),
        "publicKeyAlgorithm": ctx["credential_info"].get("publicKeyAlgorithm") or ctx["algo"],
        "signCount": getattr(ctx["auth_data"], "counter", 0),
        "createdAt": ctx["credential_info"]["registration_time"],
        "clientExtensionOutputs": credentials.convert_bytes_for_json(ctx["client_extension_results"]),
        "attestationFormat": ctx["attestation_format"],
        "attestationStatement": credentials.convert_bytes_for_json(ctx["attestation_statement"]),
        "properties": credentials.convert_bytes_for_json(ctx["credential_properties"]),
        "publicKeyCose": credentials.convert_bytes_for_json(ctx["cose_public_key"]),
        "publicKeyBytes": encode_base64url(ctx["public_key_bytes"]),
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

