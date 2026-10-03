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
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, NamedTuple

from fido2 import cbor

from ... import json_values
from ...encoding import encode_base64, encode_base64url
from ...storage import credentials
from ...webauthn import client_binary, cose_algorithms, pqc, registration_facts
from ...webauthn.attestation import aaguid as attestation_aaguid


def resolve_user_handle(user_info: Mapping[str, Any], username: str) -> Any:
    """``user.id`` decoded, or the user name's bytes when it is missing or undecodable."""

    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            return client_binary.read_request_field(user_id_value)
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
    attestation_aaguid.augment_aaguid_fields(credential_info)
    if extensions_summary:
        credential_info["authenticator_extensions"] = extensions_summary
    if attestation_certificate_details is not None:
        credential_info["attestation_certificate"] = attestation_certificate_details
    if isinstance(prepared["response"], Mapping):
        credential_info["registration_response"] = json_values.make_json_safe(prepared["response"])
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

    algo = cose_algorithms.coerce_cose_algorithm(raw_alg_value)
    credential_info["publicKeyAlgorithm"] = algo
    algoname = pqc.describe_algorithm(algo)
    pqc.log_algorithm_selection("registration", algo)
    return algo, algoname


def _cred_protect_used(extensions_requested: Mapping[str, Any]) -> Any:
    cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
    if cred_protect_requested is None:
        cred_protect_requested = extensions_requested.get("credProtect")
    if isinstance(cred_protect_requested, int):
        return attestation_aaguid.describe_cred_protect(cred_protect_requested)
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

    # An object when there (registration_options.member_type_refusal).
    extensions_requested = public_key.get("extensions", {})
    debug_info["credProtectUsed"] = _cred_protect_used(extensions_requested)

    enforce_requested = extensions_requested.get("enforceCredentialProtectionPolicy")
    if enforce_requested is None:
        enforce_requested = extensions_requested.get("enforceCredProtect")
    debug_info["enforceCredProtectUsed"] = bool(enforce_requested)
    return debug_info


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


class _Facts(NamedTuple):
    credential_id_bytes: bytes
    identifiers: dict[str, Any]  # base64, base64url, hex
    aaguid: tuple[Any, Any, Any]  # bytes, hex, GUID
    flags: dict[str, bool]
    authenticator_data: tuple[str, str]  # hex, SHA-256
    registration_timestamp: str
    rp_hash: dict[str, Any]
    rp_id_hash_valid: Any
    resident_key: bool
    large_blob: bool


def _registration_facts(
    *,
    auth_data: Any,
    credential_info: dict[str, Any],
    client_extension_results: Any,
    resolved_rp_id: str,
    resident_key_required: bool,
    attestation_rp_id_hash_valid: Any,
) -> _Facts:
    """What authData and the extension outputs say, recorded into the credential's properties."""

    properties = credential_info["properties"]
    credential_data = auth_data.credential_data
    credential_id_bytes = getattr(credential_data, "credential_id", b"") or b""
    identifiers: dict[str, Any] = {"base64": None, "base64url": None, "hex": None}
    if credential_id_bytes:
        identifiers = registration_facts.byte_forms(credential_id_bytes)

    aaguid_bytes, aaguid_hex, aaguid_guid = registration_facts.aaguid_values(credential_data)
    registration_facts.record_aaguid(properties, aaguid_hex, aaguid_guid)

    flags_dict = registration_facts.flags(auth_data)

    auth_data_bytes = bytes(auth_data)
    authenticator_data_hex = auth_data_bytes.hex()
    authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
    registration_timestamp = datetime.fromtimestamp(credential_info["registration_time"], timezone.utc).isoformat()

    rp_hash = registration_facts.rp_id_hash_report(auth_data, resolved_rp_id)
    if attestation_rp_id_hash_valid is None:
        attestation_rp_id_hash_valid = rp_hash["bytes"] == rp_hash["expectedBytes"]
    registration_facts.record_rp_id_hash(properties, rp_hash)

    resident_key_result = _resident_key_result(client_extension_results, auth_data, resident_key_required)
    properties["residentKey"] = bool(resident_key_result)
    credential_info["resident_key"] = bool(resident_key_result)
    properties["authenticatorDataHash"] = authenticator_data_hash

    return _Facts(
        credential_id_bytes=credential_id_bytes,
        identifiers=identifiers,
        aaguid=(aaguid_bytes, aaguid_hex, aaguid_guid),
        flags=flags_dict,
        authenticator_data=(authenticator_data_hex, authenticator_data_hash),
        registration_timestamp=registration_timestamp,
        rp_hash=rp_hash,
        rp_id_hash_valid=attestation_rp_id_hash_valid,
        resident_key=resident_key_result,
        large_blob=registration_facts.large_blob_result(client_extension_results),
    )


def _relying_party_info(
    facts: _Facts,
    *,
    auth_data: Any,
    attestation_format: Any,
    credential_info: Mapping[str, Any],
    client_extension_results: Any,
    attestation_checks_safe: Any,
    attestation_summary: Any,
    user_handle: bytes,
    attestation_certificate_details: Any,
    attestation_certificates_details: Any,
) -> dict[str, Any]:
    """The relying party's view of the registration, as the response reports it."""

    _aaguid_bytes, aaguid_hex, aaguid_guid = facts.aaguid
    return registration_facts.relying_party_info(
        aaguid=registration_facts.aaguid_block(aaguid_hex, aaguid_guid),
        attestation_format=attestation_format,
        attestation_object=credential_info.get("attestation_object"),
        created_at=facts.registration_timestamp,
        credential_id=facts.identifiers,
        rp_hash=facts.rp_hash,
        rp_id_hash_match=bool(facts.rp_id_hash_valid),
        authenticator_data_hash=facts.authenticator_data[1],
        device={"name": "Unknown device", "type": "unknown"},
        large_blob=facts.large_blob,
        public_key_algorithm=credential_info.get("publicKeyAlgorithm"),
        registration=registration_facts.registration_data(
            authenticator_data=facts.authenticator_data,
            client_extension_results=client_extension_results,
            flags=facts.flags,
            signature_counter=auth_data.counter,
            attestation_checks=attestation_checks_safe,
            attestation_summary=attestation_summary,
        ),
        resident_key=facts.resident_key,
        user_handle=user_handle,
        attestation_certificate=attestation_certificate_details,
        attestation_certificates=attestation_certificates_details,
    )


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
    facts = _registration_facts(
        auth_data=auth_data,
        credential_info=credential_info,
        client_extension_results=client_extension_results,
        resolved_rp_id=resolved_rp_id,
        resident_key_required=resident_key_required,
        attestation_rp_id_hash_valid=attestation_rp_id_hash_valid,
    )
    rp_info = _relying_party_info(
        facts,
        auth_data=auth_data,
        attestation_format=attestation_format,
        credential_info=credential_info,
        client_extension_results=client_extension_results,
        attestation_checks_safe=attestation_checks_safe,
        attestation_summary=attestation_summary,
        user_handle=user_handle,
        attestation_certificate_details=attestation_certificate_details,
        attestation_certificates_details=attestation_certificates_details,
    )

    credential_info["relying_party"] = json_values.make_json_safe(rp_info)

    stored_credential = _stored_credential(
        credential_info=credential_info,
        auth_data=auth_data,
        attestation_format=attestation_format,
        attestation_statement=attestation_statement,
        client_extension_results=client_extension_results,
        rp_info=rp_info,
        user_handle=user_handle,
        identifiers=facts.identifiers,
        aaguid=facts.aaguid,
        resident_key_result=facts.resident_key,
        large_blob_result=facts.large_blob,
        authenticator_data=facts.authenticator_data,
    )

    return {
        "storedCredential": stored_credential,
        "rpInfo": rp_info,
        "credentialIdBytes": facts.credential_id_bytes,
        "aaguidBytes": facts.aaguid[0],
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
    identifiers: Mapping[str, Any],
    aaguid: tuple[Any, Any, Any],
    resident_key_result: bool,
    large_blob_result: bool,
    authenticator_data: tuple[str, str],
) -> dict[str, Any]:
    """The credential record the browser keeps (and the artifact store persists)."""

    credential_id_b64url, credential_id_hex = identifiers["base64url"], identifiers["hex"]
    aaguid_bytes, aaguid_hex, aaguid_guid = aaguid
    authenticator_data_hex, authenticator_data_hash = authenticator_data

    user_handle_forms = registration_facts.byte_forms(user_handle)

    stored_properties = json_values.make_json_safe(credential_info.get("properties", {}))
    stored_extensions = json_values.make_json_safe(client_extension_results)
    public_key_b64, public_key_b64url = _public_key_encodings(auth_data)

    stored_credential = registration_facts.stored_credential({
        "type": "advanced",
        "userName": credential_info["user_info"]["name"],
        "displayName": credential_info["user_info"]["display_name"],
        "residentKey": bool(resident_key_result),
        "largeBlob": bool(large_blob_result),
        "authenticatorAttachment": credential_info.get("authenticator_attachment"),
        "credentialId": credential_id_b64url,
        "credentialIdBase64Url": credential_id_b64url,
        "credentialIdHex": credential_id_hex,
        "aaguid": encode_base64url(aaguid_bytes) if aaguid_bytes else None,
        "aaguidHex": aaguid_hex,
        "aaguidGuid": aaguid_guid,
        "publicKeyAlgorithm": credential_info.get("publicKeyAlgorithm"),
        "publicKey": public_key_b64url,
        "publicKeyBase64": public_key_b64,
        "publicKeyBase64Url": public_key_b64url,
        "publicKeyBytes": credential_info.get("publicKeyBytes"),
        "publicKeyCose": credential_info.get("publicKeyCose"),
        "publicKeyType": credential_info.get("publicKeyType"),
        "signCount": getattr(auth_data, "counter", 0),
        "createdAt": credential_info["registration_time"],
        "clientExtensionOutputs": stored_extensions,
        "attestationFormat": attestation_format,
        "attestationStatement": json_values.make_json_safe(attestation_statement),
        "attestationObject": json_values.make_json_safe(credential_info.get("attestation_object")),
        "authenticatorData": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash,
        "clientDataJSON": json_values.make_json_safe(credential_info.get("client_data_json")),
        "relyingParty": json_values.make_json_safe(rp_info),
        "properties": stored_properties,
        "registrationResponse": credential_info.get("registration_response"),
        "userHandle": user_handle_forms["base64url"],
        "userHandleBase64": user_handle_forms["base64"],
        "userHandleBase64Url": user_handle_forms["base64url"],
        "userHandleHex": user_handle_forms["hex"],
    }, drop_none=True)

    return json_values.make_json_safe(stored_credential)
