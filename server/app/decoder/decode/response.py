"""Decoder payload and result conversion helpers."""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from ...webauthn.attestation import make_json_safe, serialize_attestation_certificate
from . import binary, summary
from .binary import (
    _convert_cose_key_for_display,
    _describe_cose_key,
    _resolve_cose_algorithm,
)
from .certificates import (
    _convert_attestation_entry_impl,
    _convert_attestation_statement_impl,
    _convert_certificate_bytes_impl,
    _convert_certificate_chain_impl,
    _convert_certificate_payload_impl,
)
from .keys import hex_json_safe as _hex_json_safe
from .keys import stringify_mapping_keys as _stringify_mapping_keys


def _prepare_decoder_response(result: dict[str, Any]) -> dict[str, Any]:
    return _build_decoder_payload(result)


def _build_decoder_payload(result: dict[str, Any]) -> dict[str, Any]:
    base_type = summary._base_type(result.get("format"))
    data = _convert_result_to_data(base_type, result)
    malformed = result.get("malformed")
    if not isinstance(malformed, list):
        malformed = []

    type_label = base_type
    if base_type == "CBOR":
        decoded = result.get("decoded")
        qualifiers: list[str] = []
        if isinstance(decoded, Mapping):
            ctap_info = decoded.get("ctap")
            if isinstance(ctap_info, Mapping):
                meaning = ctap_info.get("meaning") or ctap_info.get("description")
                if isinstance(meaning, str) and meaning:
                    qualifiers.append(meaning)
            ctap_decoded = decoded.get("ctapDecoded")
            if isinstance(ctap_decoded, Mapping):
                if "makeCredentialResponse" in ctap_decoded:
                    qualifiers.append("MakeCredential response")
                if "getAssertionResponse" in ctap_decoded:
                    qualifiers.append("GetAssertion response")
                if "makeCredentialRequest" in ctap_decoded:
                    qualifiers.append("MakeCredential request")
                if "getAssertionRequest" in ctap_decoded:
                    qualifiers.append("GetAssertion request")
                if "getInfoResponse" in ctap_decoded:
                    qualifiers.append("GetInfo response")
            expanded_json = decoded.get("expandedJson")
            if isinstance(expanded_json, Mapping):
                if "attStmt" in expanded_json and "MakeCredential response" not in qualifiers:
                    qualifiers.append("MakeCredential response")
                if "signature" in expanded_json and "GetAssertion response" not in qualifiers:
                    qualifiers.append("GetAssertion response")
        if qualifiers:
            unique = []
            for qualifier in qualifiers:
                if qualifier not in unique:
                    unique.append(qualifier)
            type_label = f"{base_type} ({'; '.join(unique)})"

    findings = result.get("findings")
    return {
        "success": True,
        "type": type_label,
        "data": data,
        "decodeMode": result.get("decodeMode", "strict"),
        "findings": findings if isinstance(findings, list) else [],
        "malformed": malformed,
    }


def _convert_result_to_data(base_type: str, result: dict[str, Any]) -> Any:
    if base_type == "PublicKeyCredential":
        return _convert_public_key_credential_data(result)
    if base_type == "Attestation object":
        return _convert_attestation_object_data(result)
    if base_type == "Authenticator data":
        return _convert_authenticator_data_result(result)
    if base_type == "WebAuthn client data":
        return _convert_client_data_result(result)
    if base_type == "X.509 certificate":
        return _convert_certificate_result(result)
    if base_type == "JSON":
        return {"json": make_json_safe(result.get("decoded"))}
    if base_type == "CBOR":
        decoded = result.get("decoded")
        if isinstance(decoded, Mapping):
            payload: dict[str, Any] = {}
            if "ctapDecoded" in decoded:
                payload["ctapDecoded"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["ctapDecoded"])
                )
            if "expandedJson" in decoded:
                payload["expandedJson"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["expandedJson"])
                )
            if "decodedValue" in decoded:
                payload["decodedValue"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["decodedValue"])
                )
            if "ctap" in decoded:
                payload["ctap"] = _stringify_mapping_keys(make_json_safe(decoded["ctap"]))
            if not payload:
                payload["cbor"] = make_json_safe(decoded)
            return payload
        return {"cbor": make_json_safe(decoded)}

    decoded_value = result.get("decoded")
    if decoded_value is not None:
        return make_json_safe(decoded_value)
    binary_value = result.get("binary")
    if binary_value is not None:
        return make_json_safe(binary_value)
    return {}


def _convert_public_key_credential_data(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}

    payload: dict[str, Any] = {}

    credential_overview = _build_credential_overview(decoded)
    if credential_overview:
        payload["credential"] = credential_overview

    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    attestation_section = _convert_attestation_entry(attestation_entry)
    if attestation_section:
        payload["attestationObject"] = attestation_section

    authenticator_section = _build_authenticator_section(
        response, attestation_entry
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_data_section = _convert_client_data_entry(
        response.get("clientDataJSON") if isinstance(response, Mapping) else None
    )
    if client_data_section:
        payload["clientDataJSON"] = client_data_section

    client_extensions = decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None
    if client_extensions is not None:
        payload["clientExtensionResults"] = make_json_safe(client_extensions)

    response_extras = _collect_response_extras(response)
    if response_extras:
        payload["responseDetails"] = response_extras

    # A field that did not decode says where it stopped, in the section it names.
    for field in ("attestationObject", "authenticatorData", "clientDataJSON"):
        entry = response.get(field) if isinstance(response, Mapping) else None
        if isinstance(entry, Mapping) and "parseError" in entry:
            payload.setdefault(field, {})["parseError"] = entry["parseError"]

    return payload


def _convert_attestation_object_data(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    attestation_section = _convert_attestation_entry(decoded)
    payload: dict[str, Any] = {}
    if attestation_section:
        if "raw" not in attestation_section:
            binary_info = result.get("binary") if isinstance(result.get("binary"), Mapping) else None
            if isinstance(binary_info, Mapping):
                raw_value = binary_info.get("base64") or binary_info.get("base64url")
                if raw_value:
                    attestation_section["raw"] = raw_value
        payload["attestationObject"] = attestation_section

    authenticator_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None
    authenticator_section = _build_authenticator_data_payload(
        binary._extract_authenticator_bytes_from_attestation(decoded),
        authenticator_details,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if client_extensions:
        payload["extensions"] = make_json_safe(client_extensions)

    return payload


def _convert_authenticator_data_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    result.get("binary")
    auth_bytes = binary._extract_bytes_from_binary(result.get("binary"))
    if auth_bytes is None:
        auth_bytes = binary._extract_bytes_from_binary(decoded)
    authenticator_section = _build_authenticator_data_payload(
        auth_bytes,
        decoded,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    return authenticator_section or {}


def _convert_client_data_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    return _convert_client_data_entry(decoded) or {}


def _convert_certificate_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    if not decoded:
        return {}

    if "certificates" in decoded and isinstance(decoded["certificates"], list):
        certificates = [
            _convert_certificate_payload(entry) for entry in decoded["certificates"] if isinstance(entry, Mapping)
        ]
        return {"certificates": [cert for cert in certificates if cert]}

    certificate_payload = _convert_certificate_payload(decoded)
    return certificate_payload or {}


def _convert_attestation_entry(entry: Any) -> dict[str, Any]:
    return _convert_attestation_entry_impl(
        entry,
        convert_attestation_statement=_convert_attestation_statement,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_attestation_statement(details: Any) -> dict[str, Any]:
    payload = _convert_attestation_statement_impl(
        details,
        convert_certificate_chain=_convert_certificate_chain,
    )
    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "x5c":
            normalized[key] = value
        else:
            normalized[key] = _hex_json_safe(value)
    return normalized


def _convert_certificate_chain(value: Any) -> list[dict[str, Any]]:
    return _convert_certificate_chain_impl(
        value,
        convert_certificate_bytes=_convert_certificate_bytes,
    )


def _convert_certificate_bytes(value: Any) -> dict[str, Any]:
    return _convert_certificate_bytes_impl(
        value,
        serializer=serialize_attestation_certificate,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_certificate_payload(
    entry: Mapping[str, Any], cert_bytes: bytes | None = None
) -> dict[str, Any]:
    payload = _convert_certificate_payload_impl(entry, cert_bytes)
    parsed_entry = payload.get("parsedX5c")
    if parsed_entry is not None:
        payload["parsedX5c"] = _hex_json_safe(parsed_entry)
    return payload


def _build_authenticator_section(
    response: Any,
    attestation_entry: Any,
) -> dict[str, Any]:
    response_mapping = response if isinstance(response, Mapping) else {}
    attestation_mapping = attestation_entry if isinstance(attestation_entry, Mapping) else {}

    auth_bytes = binary._extract_authenticator_bytes(response_mapping, attestation_entry)

    details = None
    auth_entry = response_mapping.get("authenticatorData")
    if isinstance(auth_entry, Mapping):
        details = auth_entry.get("details")
    if details is None and isinstance(attestation_mapping.get("details"), Mapping):
        details = attestation_mapping["details"].get("authenticatorData")

    fallback_alg = None
    if isinstance(response_mapping, Mapping):
        fallback_alg = response_mapping.get("publicKeyAlgorithm")

    return _build_authenticator_data_payload(auth_bytes, details, fallback_alg)


def _build_credential_overview(decoded: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(decoded, Mapping):
        return {}

    overview: dict[str, Any] = {}
    for key in ("id", "type", "authenticatorAttachment"):
        value = decoded.get(key)
        if value is not None:
            overview[key] = value

    transports = decoded.get("transports")
    if transports is not None:
        overview["transports"] = make_json_safe(transports)

    raw_id = decoded.get("rawId")
    if isinstance(raw_id, Mapping):
        raw_payload: dict[str, Any] = {}
        raw_value = raw_id.get("raw")
        if raw_value is not None:
            raw_payload["raw"] = raw_value
        binary = raw_id.get("binary")
        if binary is not None:
            raw_payload["binary"] = make_json_safe(binary)
        if raw_payload:
            overview["rawId"] = raw_payload
    elif raw_id is not None:
        overview["rawId"] = raw_id

    raw_json = decoded.get("rawJson")
    if isinstance(raw_json, str) and raw_json.strip():
        overview["rawJson"] = raw_json

    return overview


def _build_authenticator_data_payload(
    auth_bytes: bytes | None,
    details: Any,
    fallback_alg: Any | None = None,
) -> dict[str, Any]:
    if auth_bytes is None and not isinstance(details, Mapping):
        return {}

    payload: dict[str, Any] = {}

    if auth_bytes is not None:
        payload["raw"] = auth_bytes.hex()

    rp_hash_hex = None
    if isinstance(details, Mapping):
        rp_info = details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hash_hex = rp_info.get("hex") or rp_info.get("value")
        elif isinstance(rp_info, str):
            rp_hash_hex = rp_info
    if rp_hash_hex is None and auth_bytes is not None and len(auth_bytes) >= 32:
        rp_hash_hex = auth_bytes[:32].hex()
    if rp_hash_hex:
        payload["rpIdHash"] = rp_hash_hex

    flags_info = details.get("flags") if isinstance(details, Mapping) else None
    flags_byte = auth_bytes[32] if auth_bytes is not None and len(auth_bytes) > 32 else None
    auth_length = len(auth_bytes) if auth_bytes is not None else None
    flags_payload = _build_flag_payload(flags_info, flags_byte, auth_length)
    if flags_payload:
        payload["flags"] = flags_payload

    counter_value = None
    if isinstance(details, Mapping):
        counter_value = details.get("signCount")
    if counter_value is None and auth_bytes is not None and len(auth_bytes) >= 37:
        counter_value = int.from_bytes(auth_bytes[33:37], "big")
    if counter_value is not None:
        try:
            payload["counter"] = int(counter_value)
        except (TypeError, ValueError):
            payload["counter"] = counter_value

    credential_details = details.get("attestedCredentialData") if isinstance(details, Mapping) else None
    credential_payload = _build_credential_payload(credential_details, auth_bytes, fallback_alg)
    if credential_payload:
        payload["credential"] = credential_payload

    extensions = details.get("extensions") if isinstance(details, Mapping) else None
    if extensions is not None:
        payload["extensions"] = make_json_safe(extensions)

    return payload


def _build_flag_payload(
    flag_details: Any,
    flags_byte: int | None,
    auth_byte_length: int | None = None,
) -> dict[str, Any]:
    if flag_details is None and flags_byte is None:
        return {}

    if flag_details is None and auth_byte_length is not None and auth_byte_length < 37:
        return {}

    payload: dict[str, Any] = {}

    bitfield = None
    hex_value = None
    up = uv = be = bs = at = ed = None

    if isinstance(flag_details, Mapping):
        bitfield = flag_details.get("bitfield")
        value = flag_details.get("value")
        try:
            hex_value = f"{int(value):02x}".upper()
        except (TypeError, ValueError):
            hex_value = None
        up = flag_details.get("userPresent")
        uv = flag_details.get("userVerified")
        be = flag_details.get("backupEligible")
        bs = flag_details.get("backupState")
        at = flag_details.get("attestedCredentialData")
        ed = flag_details.get("extensionData")
        if flags_byte is None:
            try:
                flags_byte = int(value)
            except (TypeError, ValueError):
                flags_byte = None

    if flags_byte is not None:
        if bitfield is None:
            bitfield = f"{flags_byte:08b}"
        if hex_value is None:
            hex_value = f"{flags_byte:02x}".upper()
        if up is None:
            up = bool(flags_byte & 0x01)
        if uv is None:
            uv = bool(flags_byte & 0x04)
        if be is None:
            be = bool(flags_byte & 0x08)
        if bs is None:
            bs = bool(flags_byte & 0x10)
        if at is None:
            at = bool(flags_byte & 0x40)
        if ed is None:
            ed = bool(flags_byte & 0x80)

    if bitfield:
        payload["bin"] = bitfield.replace("0b", "")[-8:].zfill(8)
    if hex_value:
        payload["hex"] = hex_value
        payload["raw"] = hex_value
    if up is not None:
        payload["UP"] = bool(up)
    if uv is not None:
        payload["UV"] = bool(uv)
    if be is not None:
        payload["BE"] = bool(be)
    if bs is not None:
        payload["BS"] = bool(bs)
    if at is not None:
        payload["AT"] = bool(at)
    if ed is not None:
        payload["ED"] = bool(ed)

    return payload


def _build_credential_payload(
    credential_details: Any,
    auth_bytes: bytes | None,
    fallback_alg: Any | None = None,
) -> dict[str, Any]:
    if credential_details is None and auth_bytes is None:
        return {}

    aaguid_hex = None
    aaguid_uuid = None
    credential_id_hex = None
    credential_id_length = None
    cose_key: Mapping[str, Any] | None = None

    if isinstance(credential_details, Mapping):
        aaguid_uuid = credential_details.get("aaguid")
        aaguid_hex = credential_details.get("aaguidHex")
        credential_id_info = credential_details.get("credentialId")
        if isinstance(credential_id_info, Mapping):
            credential_id_hex = credential_id_info.get("hex")
            length_value = credential_id_info.get("length")
            try:
                credential_id_length = f"{int(length_value):04x}".upper()
            except (TypeError, ValueError):
                if isinstance(length_value, str):
                    credential_id_length = length_value
        public_key_info = credential_details.get("publicKey")
        if isinstance(public_key_info, Mapping):
            cose_key = public_key_info

    attested_raw_hex = None
    public_key_raw_hex = None
    if auth_bytes is not None and len(auth_bytes) > 37:
        attested_bytes = auth_bytes[37:]
        attested_raw_hex = attested_bytes.hex()
        if len(attested_bytes) >= 18:
            aaguid_bytes = attested_bytes[:16]
            length_bytes = attested_bytes[16:18]
            cred_length = int.from_bytes(length_bytes, "big")
            credential_bytes = attested_bytes[18 : 18 + cred_length]
            public_key_bytes = attested_bytes[18 + cred_length :]
            if not aaguid_hex:
                aaguid_hex = aaguid_bytes.hex()
            if not aaguid_uuid:
                try:
                    aaguid_uuid = str(uuid.UUID(bytes=aaguid_bytes))
                except Exception:
                    aaguid_uuid = None
            if credential_id_hex is None:
                credential_id_hex = credential_bytes.hex()
            if credential_id_length is None:
                credential_id_length = f"{cred_length:04x}".upper()
            if public_key_bytes:
                public_key_raw_hex = public_key_bytes.hex()

    public_key_payload: dict[str, Any] = {}
    if cose_key is not None:
        cose_display = _convert_cose_key_for_display(cose_key)
        public_key_payload["cose"] = make_json_safe(cose_display)
        alg_label = _resolve_cose_algorithm(cose_key, fallback_alg)
    else:
        alg_label = _resolve_cose_algorithm({}, fallback_alg)
    if alg_label is not None:
        public_key_payload["alg"] = alg_label
    public_key_payload.update(_describe_cose_key(cose_key))
    if public_key_raw_hex:
        public_key_payload["raw"] = public_key_raw_hex
    if not public_key_payload:
        public_key_payload = {}

    credential_payload: dict[str, Any] = {}
    if attested_raw_hex:
        credential_payload["raw"] = attested_raw_hex
    if aaguid_hex or aaguid_uuid:
        aaguid_payload: dict[str, Any] = {}
        if aaguid_hex:
            aaguid_payload["raw"] = aaguid_hex
        if aaguid_uuid:
            aaguid_payload["uuid"] = aaguid_uuid
        credential_payload["aaguid"] = aaguid_payload
    if credential_id_length:
        credential_payload["credentialIdLength"] = credential_id_length
    if credential_id_hex:
        credential_payload["credentialId"] = credential_id_hex
    if public_key_payload:
        credential_payload["publicKey"] = public_key_payload

    return credential_payload


def _convert_client_data_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    if not isinstance(details, Mapping):
        return {}

    payload: dict[str, Any] = {}
    for key in ("type", "origin", "crossOrigin"):
        if key in details:
            payload[key] = make_json_safe(details.get(key))

    challenge_info = details.get("challenge")
    if isinstance(challenge_info, Mapping):
        challenge_value = (
            challenge_info.get("raw")
            or challenge_info.get("base64url")
            or challenge_info.get("base64")
        )
        if challenge_value is not None:
            payload["challenge"] = challenge_value
        else:
            payload["challenge"] = make_json_safe(challenge_info)
    elif details.get("challenge") is not None:
        payload["challenge"] = details.get("challenge")

    return payload


def _collect_response_extras(response: Any) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        return {}

    extras: dict[str, Any] = {}
    for field in ("signature", "userHandle", "publicKey", "publicKeyAlgorithm"):
        if field in response and response[field] is not None:
            extras[field] = make_json_safe(response[field])

    return extras
