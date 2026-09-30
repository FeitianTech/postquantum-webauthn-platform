"""The decoder's answer, built from what a reading returned (``_prepare_decoder_response``).

Its ``type`` names what was read, ``data`` shows it for the page, and the
findings and what was skipped come with it.
"""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ... import encoding
from ...json_values import make_json_safe
from .. import values
from . import cbor_parser, certificates
from .binary import (
    _convert_cose_key_for_display,
    _describe_cose_key,
    _resolve_cose_algorithm,
)


def _base_type(format_label: str | None) -> str:
    if not format_label:
        return "Decoded data"
    separator = format_label.find(" (")
    if separator != -1:
        return format_label[:separator]
    return format_label


def _prepare_decoder_response(result: dict[str, Any]) -> dict[str, Any]:
    return _build_decoder_payload(result)


def _build_decoder_payload(result: dict[str, Any]) -> dict[str, Any]:
    base_type = _base_type(result.get("format"))
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
        if qualifiers:
            unique = []
            for qualifier in qualifiers:
                if qualifier not in unique:
                    unique.append(qualifier)
            type_label = f"{base_type} ({'; '.join(unique)})"

    # What is interpreted beside the decoded value goes next to it, never over it.
    extra = result.get("extraData")
    if isinstance(extra, Mapping) and isinstance(data, dict):
        data.update(extra)

    findings = result.get("findings")
    return {
        "success": True,
        "type": type_label,
        # A map whose keys JSON would spell alike still arrives whole.
        "data": values.json_ready(data),
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
                payload["ctapDecoded"] = values.stringify_mapping_keys(
                    values.make_hex_only(decoded["ctapDecoded"])
                )
            if "expandedJson" in decoded:
                payload["expandedJson"] = values.stringify_mapping_keys(
                    values.make_hex_only(decoded["expandedJson"])
                )
            if "decodedValue" in decoded:
                payload["decodedValue"] = values.stringify_mapping_keys(
                    values.make_hex_only(decoded["decodedValue"])
                )
            if "ctap" in decoded:
                payload["ctap"] = values.stringify_mapping_keys(make_json_safe(decoded["ctap"]))
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
    attestation_section = certificates.convert_attestation_entry(attestation_entry)
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

    attestation_section = certificates.convert_attestation_entry(decoded)
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
        _extract_authenticator_bytes_from_attestation(decoded),
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
    auth_bytes = _extract_bytes_from_binary(result.get("binary"))
    if auth_bytes is None:
        auth_bytes = _extract_bytes_from_binary(decoded)
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
        converted = [
            certificates.convert_certificate_payload(entry) for entry in decoded["certificates"] if isinstance(entry, Mapping)
        ]
        return {"certificates": [cert for cert in converted if cert]}

    certificate_payload = certificates.convert_certificate_payload(decoded)
    return certificate_payload or {}


def _build_authenticator_section(
    response: Any,
    attestation_entry: Any,
) -> dict[str, Any]:
    response_mapping = response if isinstance(response, Mapping) else {}
    attestation_mapping = attestation_entry if isinstance(attestation_entry, Mapping) else {}

    auth_bytes = _extract_authenticator_bytes(response_mapping, attestation_entry)

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


@dataclass
class _CredentialFacts:
    """What the answer shows of attested credential data: from the decoded details, else from the bytes."""

    aaguid_hex: Any = None
    aaguid_uuid: Any = None
    credential_id_hex: Any = None
    credential_id_length: Any = None
    cose_key: Mapping[str, Any] | None = None
    attested_raw_hex: str | None = None
    public_key_raw_hex: str | None = None


def _build_credential_payload(
    credential_details: Any,
    auth_bytes: bytes | None,
    fallback_alg: Any | None = None,
) -> dict[str, Any]:
    if credential_details is None and auth_bytes is None:
        return {}

    facts = _CredentialFacts()
    _read_credential_details(facts, credential_details)
    _read_attested_bytes(facts, auth_bytes)
    return _credential_payload(facts, _public_key_payload(facts, fallback_alg))


def _read_credential_details(facts: _CredentialFacts, credential_details: Any) -> None:
    if not isinstance(credential_details, Mapping):
        return

    facts.aaguid_uuid = credential_details.get("aaguid")
    facts.aaguid_hex = credential_details.get("aaguidHex")
    credential_id_info = credential_details.get("credentialId")
    if isinstance(credential_id_info, Mapping):
        facts.credential_id_hex = credential_id_info.get("hex")
        length_value = credential_id_info.get("length")
        try:
            facts.credential_id_length = f"{int(length_value):04x}".upper()
        except (TypeError, ValueError):
            if isinstance(length_value, str):
                facts.credential_id_length = length_value
    public_key_info = credential_details.get("publicKey")
    if isinstance(public_key_info, Mapping):
        facts.cose_key = public_key_info


def _read_attested_bytes(facts: _CredentialFacts, auth_bytes: bytes | None) -> None:
    """Fill in from the attested credential data bytes whatever the decoded details did not give."""

    if auth_bytes is None or len(auth_bytes) <= 37:
        return

    attested_bytes = auth_bytes[37:]
    facts.attested_raw_hex = attested_bytes.hex()
    if len(attested_bytes) < 18:
        return

    aaguid_bytes = attested_bytes[:16]
    length_bytes = attested_bytes[16:18]
    cred_length = int.from_bytes(length_bytes, "big")
    credential_bytes = attested_bytes[18 : 18 + cred_length]
    public_key_bytes = attested_bytes[18 + cred_length :]
    if not facts.aaguid_hex:
        facts.aaguid_hex = aaguid_bytes.hex()
    if not facts.aaguid_uuid:
        try:
            facts.aaguid_uuid = str(uuid.UUID(bytes=aaguid_bytes))
        except Exception:
            facts.aaguid_uuid = None
    if facts.credential_id_hex is None:
        facts.credential_id_hex = credential_bytes.hex()
    if facts.credential_id_length is None:
        facts.credential_id_length = f"{cred_length:04x}".upper()
    if public_key_bytes:
        facts.public_key_raw_hex = public_key_bytes.hex()


def _public_key_payload(facts: _CredentialFacts, fallback_alg: Any | None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if facts.cose_key is not None:
        payload["cose"] = make_json_safe(_convert_cose_key_for_display(facts.cose_key))
        alg_label = _resolve_cose_algorithm(facts.cose_key, fallback_alg)
    else:
        alg_label = _resolve_cose_algorithm({}, fallback_alg)
    if alg_label is not None:
        payload["alg"] = alg_label
    payload.update(_describe_cose_key(facts.cose_key))
    if facts.public_key_raw_hex:
        payload["raw"] = facts.public_key_raw_hex
    return payload


def _credential_payload(facts: _CredentialFacts, public_key_payload: dict[str, Any]) -> dict[str, Any]:
    credential_payload: dict[str, Any] = {}
    if facts.attested_raw_hex:
        credential_payload["raw"] = facts.attested_raw_hex
    if facts.aaguid_hex or facts.aaguid_uuid:
        aaguid_payload: dict[str, Any] = {}
        if facts.aaguid_hex:
            aaguid_payload["raw"] = facts.aaguid_hex
        if facts.aaguid_uuid:
            aaguid_payload["uuid"] = facts.aaguid_uuid
        credential_payload["aaguid"] = aaguid_payload
    if facts.credential_id_length:
        credential_payload["credentialIdLength"] = facts.credential_id_length
    if facts.credential_id_hex:
        credential_payload["credentialId"] = facts.credential_id_hex
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


def _extract_hex_from_binary(entry: Any) -> str | None:
    if not isinstance(entry, Mapping):
        return None
    direct_hex = entry.get("hex")
    if isinstance(direct_hex, str) and direct_hex:
        return direct_hex
    binary = entry.get("binary")
    if isinstance(binary, Mapping):
        hex_value = binary.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def _extract_bytes_from_binary(entry: Any) -> bytes | None:
    if not isinstance(entry, Mapping):
        return None
    hex_value = _extract_hex_from_binary(entry)
    if isinstance(hex_value, str):
        decoded = encoding.try_decode_hex(hex_value)
        if decoded is not None:
            return decoded

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        return encoding.try_decode_base64url(raw_value)

    return None


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> bytes | None:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = _extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return _extract_authenticator_bytes_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> bytes | None:
    attestation_bytes = _extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            attestation_bytes = encoding.try_decode_base64(raw_value)

    if attestation_bytes is None:
        return None

    try:
        node, _, _ = cbor_parser.decode_item(attestation_bytes)
    except ValueError:
        return None
    attestation = cbor_parser._structure_to_value(node)
    auth_data = attestation.get("authData") if isinstance(attestation, Mapping) else None
    return auth_data if isinstance(auth_data, bytes) else None
