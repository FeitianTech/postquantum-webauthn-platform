"""Leaf conversion helpers used by decoder result payload builders."""
from __future__ import annotations

import uuid
from typing import Any, Dict, Mapping, Optional

from ...attestation import make_json_safe
from .binary_extract import (
    _convert_cose_key_for_display,
    _resolve_cose_algorithm,
)


def _build_credential_overview(decoded: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(decoded, Mapping):
        return {}

    overview: Dict[str, Any] = {}
    for key in ("id", "type", "authenticatorAttachment"):
        value = decoded.get(key)
        if value is not None:
            overview[key] = value

    transports = decoded.get("transports")
    if transports is not None:
        overview["transports"] = make_json_safe(transports)

    raw_id = decoded.get("rawId")
    if isinstance(raw_id, Mapping):
        raw_payload: Dict[str, Any] = {}
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
    auth_bytes: Optional[bytes],
    details: Any,
    fallback_alg: Optional[Any] = None,
) -> Dict[str, Any]:
    if auth_bytes is None and not isinstance(details, Mapping):
        return {}

    payload: Dict[str, Any] = {}

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
    flags_byte: Optional[int],
    auth_byte_length: Optional[int] = None,
) -> Dict[str, Any]:
    if flag_details is None and flags_byte is None:
        return {}

    if flag_details is None and auth_byte_length is not None and auth_byte_length < 37:
        return {}

    payload: Dict[str, Any] = {}

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
    auth_bytes: Optional[bytes],
    fallback_alg: Optional[Any] = None,
) -> Dict[str, Any]:
    if credential_details is None and auth_bytes is None:
        return {}

    aaguid_hex = None
    aaguid_uuid = None
    credential_id_hex = None
    credential_id_length = None
    cose_key: Optional[Mapping[str, Any]] = None

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

    public_key_payload: Dict[str, Any] = {}
    if cose_key is not None:
        cose_display = _convert_cose_key_for_display(cose_key)
        public_key_payload["cose"] = make_json_safe(cose_display)
        alg_label = _resolve_cose_algorithm(cose_key, fallback_alg)
    else:
        alg_label = _resolve_cose_algorithm({}, fallback_alg)
    if alg_label is not None:
        public_key_payload["alg"] = alg_label
    if public_key_raw_hex:
        public_key_payload["raw"] = public_key_raw_hex
    if not public_key_payload:
        public_key_payload = {}

    credential_payload: Dict[str, Any] = {}
    if attested_raw_hex:
        credential_payload["raw"] = attested_raw_hex
    if aaguid_hex or aaguid_uuid:
        aaguid_payload: Dict[str, Any] = {}
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


def _convert_client_data_entry(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    if not isinstance(details, Mapping):
        return {}

    payload: Dict[str, Any] = {}
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


def _collect_response_extras(response: Any) -> Dict[str, Any]:
    if not isinstance(response, Mapping):
        return {}

    extras: Dict[str, Any] = {}
    for field in ("signature", "userHandle", "publicKey", "publicKeyAlgorithm"):
        if field in response and response[field] is not None:
            extras[field] = make_json_safe(response[field])

    return extras
