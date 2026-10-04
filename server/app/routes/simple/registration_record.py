"""Simple registration complete: the record of a verified registration.

Each step reads and fills one ``SimpleRegistration``: the attestation summary
and the credential's info and properties, the authenticator data, the
relying-party and debug views, then the credential the browser keeps. The
stored record is JSON, so the order these add keys in is part of the output.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fido2 import cbor

from ... import json_values
from ...encoding import encode_base64url
from ...storage import credentials
from ...webauthn import cose_algorithms, pqc, registration_facts


@dataclass
class SimpleRegistration:
    """One Simple registration as it completes; each stage fills its own fields.

    ``register_complete`` gives what the request carried and fido2 verified;
    ``initialize_registration_context`` the attestation summary and the
    credential's info; ``populate_authenticator_data_context`` what authData
    says; ``populate_rp_debug_context`` the relying party's view and the debug
    view; ``build_stored_credential_context`` the record the browser keeps.
    """

    # What the request carried and fido2 verified.
    uname: Any
    response: Any
    attestation_format: Any
    attestation_statement: Any
    parsed_attestation_object: Any
    attestation_certificate_details: Any
    attestation_certificates_details: Any
    client_data_json: Any
    client_extension_results: Any
    min_pin_length_value: Any
    auth_data: Any
    authenticator_attachment_response: Any
    raw_attestation_object_b64: Any
    resolved_rp_id: Any
    attestation_signature_valid: Any
    attestation_root_valid: Any
    attestation_rp_id_hash_valid: Any
    attestation_aaguid_match: Any
    attestation_checks_safe: Any
    # The attestation summary and the credential's info.
    metadata_summary: Any = None
    warnings: list[str] = field(default_factory=list)
    attestation_summary: dict[str, Any] = field(default_factory=dict)
    credential_info: dict[str, Any] = field(default_factory=dict)
    credential_properties: dict[str, Any] = field(default_factory=dict)
    # What authData says.
    authenticator_data_raw: str = ""
    authenticator_data_hex: str = ""
    authenticator_data_hash: str = ""
    algo: Any = None
    algoname: str = ""
    flags_value: int = 0
    flags_dict: dict[str, bool] = field(default_factory=dict)
    rp_hash: dict[str, Any] = field(default_factory=dict)
    # The relying party's view and the debug view.
    credential_id_hex: str = ""
    credential_id_b64u: str = ""
    aaguid_bytes: bytes = b""
    cose_public_key: dict[Any, Any] = field(default_factory=dict)
    public_key_bytes: bytes = b""
    user_handle_b64u: str = ""
    rp_info: dict[str, Any] = field(default_factory=dict)
    debug_info: dict[str, Any] = field(default_factory=dict)
    # The record the browser keeps.
    stored_credential: dict[str, Any] = field(default_factory=dict)


def _attestation_summary(reg: SimpleRegistration) -> tuple[dict[str, Any], Any, list[str]]:
    """The attestation summary, the metadata summary, and the attestation warnings as text."""

    attestation_summary = {
        "signatureValid": reg.attestation_signature_valid,
        "rootValid": reg.attestation_root_valid,
        "rpIdHashValid": reg.attestation_rp_id_hash_valid,
        "aaguidMatch": reg.attestation_aaguid_match,
    }

    metadata_summary = reg.attestation_checks_safe.get("metadata")
    if isinstance(metadata_summary, Mapping):
        attestation_summary["metadata"] = metadata_summary

    warnings_summary = reg.attestation_checks_safe.get("warnings")
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


def _credential_info(reg: SimpleRegistration) -> dict[str, Any]:
    return {
        "credential_data": reg.auth_data.credential_data,
        "auth_data": reg.auth_data,
        "user_info": {
            "name": reg.uname,
            "display_name": reg.uname,
            "user_handle": reg.uname.encode("utf-8"),
        },
        "registration_time": time.time(),
        "client_data_json": reg.client_data_json or "",
        "attestation_object": reg.raw_attestation_object_b64 or "",
        "attestation_object_raw": reg.raw_attestation_object_b64 or "",
        "attestation_format": reg.attestation_format,
        "attestation_statement": reg.attestation_statement,
        "attestation_certificate": reg.attestation_certificate_details,
        "attestation_certificates": reg.attestation_certificates_details,
        "client_extension_outputs": reg.client_extension_results,
        "authenticator_attachment": reg.authenticator_attachment_response,
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
            "credentialIdLength": len(reg.auth_data.credential_data.credential_id),
            "fakeCredentialIdLengthRequested": None,
            "hintsSent": [],
            "resolvedAuthenticatorAttachments": [],
            "authenticatorAttachment": reg.authenticator_attachment_response,
            "largeBlobRequested": {},
            "largeBlobClientOutput": reg.client_extension_results.get("largeBlob", {}),
            "residentKeyRequested": None,
            "residentKeyRequired": False,
        },
    }


def initialize_registration_context(reg: SimpleRegistration) -> None:
    attestation_summary, metadata_summary, warnings = _attestation_summary(reg)
    credential_info = _credential_info(reg)

    credential_properties = credential_info["properties"]
    credential_properties["attestationSignatureValid"] = reg.attestation_signature_valid
    credential_properties["attestationRootValid"] = reg.attestation_root_valid
    credential_properties["attestationRpIdHashValid"] = reg.attestation_rp_id_hash_valid
    credential_properties["attestationAaguidMatch"] = reg.attestation_aaguid_match
    credential_properties["attestationChecks"] = reg.attestation_checks_safe
    credential_properties["attestationSummary"] = attestation_summary
    if warnings:
        credential_properties["attestationWarnings"] = warnings

    if reg.min_pin_length_value is not None:
        credential_properties["minPinLength"] = reg.min_pin_length_value

    credentials.add_public_key_material(
        credential_info,
        getattr(reg.auth_data.credential_data, "public_key", {}),
    )

    credential_info["attestation_object_decoded"] = json_values.make_json_safe(reg.parsed_attestation_object)

    if reg.attestation_certificates_details:
        credential_info["attestationCertificates"] = reg.attestation_certificates_details
        credential_properties["attestationCertificates"] = reg.attestation_certificates_details

    if isinstance(reg.response, Mapping):
        credential_info["registration_response"] = json_values.make_json_safe(reg.response)

    _aaguid_bytes, aaguid_hex, aaguid_guid = registration_facts.aaguid_values(reg.auth_data.credential_data)
    registration_facts.record_aaguid(credential_properties, aaguid_hex, aaguid_guid)

    reg.metadata_summary = metadata_summary
    reg.warnings = warnings
    reg.attestation_summary = attestation_summary
    reg.credential_info = credential_info
    reg.credential_properties = credential_properties


def populate_authenticator_data_context(reg: SimpleRegistration) -> None:
    try:
        auth_data_bytes = bytes(reg.auth_data)
    except Exception:
        auth_data_bytes = b""

    authenticator_data_raw = ""
    authenticator_data_hex = ""
    authenticator_data_hash = ""
    if auth_data_bytes:
        authenticator_data_raw = encode_base64url(auth_data_bytes)
        authenticator_data_hex = auth_data_bytes.hex()
        authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
        reg.credential_info["authenticator_data_raw"] = authenticator_data_raw
        reg.credential_info["authenticator_data_hex"] = authenticator_data_hex
        reg.credential_info["authenticator_data_hash"] = authenticator_data_hash
        reg.credential_properties["authenticatorDataHash"] = authenticator_data_hash

    algo = reg.auth_data.credential_data.public_key[3]
    # Named as the advanced route names it: the one COSE name table is
    # ``pqc.describe_algorithm``. A crafted key's alg need not be an int, or even
    # hashable; the coercion gives None ("Unknown") for one it cannot read.
    algoname = pqc.describe_algorithm(cose_algorithms.coerce_cose_algorithm(algo))

    flags_value = getattr(reg.auth_data, "flags", 0)
    flags_dict = registration_facts.flags(reg.auth_data)

    rp_hash = registration_facts.rp_id_hash_report(reg.auth_data, reg.resolved_rp_id)
    if reg.attestation_rp_id_hash_valid is None:
        reg.attestation_rp_id_hash_valid = rp_hash["bytes"] == rp_hash["expectedBytes"]
    registration_facts.record_rp_id_hash(reg.credential_properties, rp_hash)

    reg.authenticator_data_raw = authenticator_data_raw
    reg.authenticator_data_hex = authenticator_data_hex
    reg.authenticator_data_hash = authenticator_data_hash
    reg.algo = algo
    reg.algoname = algoname
    reg.flags_value = flags_value
    reg.flags_dict = flags_dict
    reg.rp_hash = rp_hash


def _user_handle_bytes(user_info: Mapping[str, Any]) -> bytes:
    user_handle_value = user_info.get("user_handle")
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        return bytes(user_handle_value)
    return str(user_handle_value or "").encode("utf-8")


def _relying_party_info(
    reg: SimpleRegistration,
    *,
    registration_timestamp: str,
    credential_id_forms: Mapping[str, str],
    aaguid: tuple[bytes, str | None, str | None],
    large_blob_result: bool,
    user_handle_bytes: bytes,
) -> dict[str, Any]:
    """The relying party's view of the registration, as the answer reports it."""

    aaguid_bytes, aaguid_hex, aaguid_guid = aaguid
    authenticator_data = (reg.authenticator_data_hex, reg.authenticator_data_hash)
    return registration_facts.relying_party_info(
        aaguid=registration_facts.aaguid_block(aaguid_hex, aaguid_guid) if aaguid_bytes else None,
        attestation_format=reg.attestation_format,
        created_at=registration_timestamp,
        credential_id=credential_id_forms,
        rp_hash=reg.rp_hash,
        rp_id_hash_match=bool(reg.attestation_rp_id_hash_valid),
        authenticator_data_hash=reg.authenticator_data_hash,
        large_blob=large_blob_result,
        public_key_algorithm=reg.algo,
        registration=registration_facts.registration_data(
            authenticator_data=authenticator_data,
            client_extension_results=reg.client_extension_results,
            flags=reg.flags_dict,
            signature_counter=getattr(reg.auth_data, "counter", 0),
            attestation_checks=reg.attestation_checks_safe,
            attestation_summary=reg.attestation_summary,
            warnings=reg.warnings,
        ),
        user_handle=user_handle_bytes,
    )


def _debug_info(reg: SimpleRegistration) -> dict[str, Any]:
    return {
        "attestationFormat": reg.attestation_format,
        "algorithmsUsed": [reg.algo],
        "excludeCredentialsUsed": False,
        "hintsUsed": [],
        "credProtectUsed": "none",
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(reg.flags_value & getattr(reg.auth_data.FLAG, "BE", 0)),
        "attestationSummary": reg.attestation_summary,
        "rpIdHashValid": reg.attestation_rp_id_hash_valid,
        "rpIdHash": reg.rp_hash["hex"],
        "rpIdHashExpected": reg.rp_hash["expectedHex"],
    }


def populate_rp_debug_context(reg: SimpleRegistration) -> None:
    registration_timestamp = datetime.fromtimestamp(
        reg.credential_info["registration_time"], timezone.utc
    ).isoformat()
    large_blob_result = registration_facts.large_blob_result(reg.client_extension_results)

    credential_id_forms = registration_facts.byte_forms(reg.auth_data.credential_data.credential_id)

    aaguid_bytes, aaguid_hex, aaguid_guid = registration_facts.aaguid_values(reg.auth_data.credential_data)
    aaguid_bytes = aaguid_bytes or b""

    cose_public_key = dict(getattr(reg.auth_data.credential_data, "public_key", {}))
    public_key_bytes = cbor.encode(cose_public_key)
    user_handle_bytes = _user_handle_bytes(reg.credential_info["user_info"])

    rp_info = _relying_party_info(
        reg,
        registration_timestamp=registration_timestamp,
        credential_id_forms=credential_id_forms,
        aaguid=(aaguid_bytes, aaguid_hex, aaguid_guid),
        large_blob_result=large_blob_result,
        user_handle_bytes=user_handle_bytes,
    )
    reg.credential_info["relying_party"] = json_values.make_json_safe(rp_info)
    debug_info = _debug_info(reg)

    reg.credential_id_hex = credential_id_forms["hex"]
    reg.credential_id_b64u = credential_id_forms["base64url"]
    reg.aaguid_bytes = aaguid_bytes
    reg.cose_public_key = cose_public_key
    reg.public_key_bytes = public_key_bytes
    reg.user_handle_b64u = encode_base64url(user_handle_bytes)
    reg.rp_info = rp_info
    reg.debug_info = debug_info


def build_stored_credential_context(reg: SimpleRegistration) -> None:
    stored_credential = registration_facts.stored_credential({
        "type": "simple",
        "email": reg.uname,
        "userName": reg.credential_info["user_info"].get("name", reg.uname),
        "displayName": reg.credential_info["user_info"].get("display_name", reg.uname),
        "credentialId": reg.credential_id_b64u,
        "credentialIdBase64Url": reg.credential_id_b64u,
        "credentialIdHex": reg.credential_id_hex,
        "aaguid": encode_base64url(reg.aaguid_bytes)
        if reg.aaguid_bytes
        else None,
        "aaguidHex": reg.aaguid_bytes.hex() if reg.aaguid_bytes else None,
        "publicKey": encode_base64url(reg.public_key_bytes),
        "publicKeyBase64Url": encode_base64url(reg.public_key_bytes),
        "publicKeyAlgorithm": reg.credential_info.get("publicKeyAlgorithm") or reg.algo,
        "signCount": getattr(reg.auth_data, "counter", 0),
        "createdAt": reg.credential_info["registration_time"],
        "clientExtensionOutputs": json_values.make_json_safe(reg.client_extension_results),
        "attestationFormat": reg.attestation_format,
        "attestationStatement": json_values.make_json_safe(reg.attestation_statement),
        "properties": json_values.make_json_safe(reg.credential_properties),
        "publicKeyCose": json_values.make_json_safe(reg.cose_public_key),
        "publicKeyBytes": encode_base64url(reg.public_key_bytes),
        "authenticatorAttachment": reg.authenticator_attachment_response,
        "clientDataJSON": reg.credential_info.get("client_data_json"),
        "attestationObject": reg.credential_info.get("attestation_object"),
        "authenticatorData": reg.authenticator_data_raw,
        "authenticatorDataHex": reg.authenticator_data_hex,
        "authenticatorDataHash": reg.authenticator_data_hash or None,
        "relyingParty": json_values.make_json_safe(reg.rp_info),
        "registrationResponse": reg.credential_info.get("registration_response"),
        "userHandle": reg.user_handle_b64u,
    })
    reg.stored_credential = stored_credential


def build_register_complete_response_payload(reg: SimpleRegistration) -> dict[str, Any]:
    response_payload: dict[str, Any] = {
        "status": "OK",
        "algo": reg.algoname,
        **reg.debug_info,
        "storedCredential": json_values.make_json_safe(reg.stored_credential),
        "relyingParty": reg.rp_info,
    }
    if reg.warnings:
        response_payload["warnings"] = reg.warnings
    return response_payload

