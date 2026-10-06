"""The decoder answer's view of authenticator data: rpIdHash, flags, counter, the attested credential and extensions.

Each part is read from the decoded details where the reading gave them, else from
the bytes themselves.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ... import aaguid
from ...json_values import make_json_safe
from . import cose_display


def build_authenticator_data_payload(
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


@dataclass
class _FlagFacts:
    """Flags as the details name them, filled from their byte when absent."""

    flags_byte: int | None = None
    bitfield: Any = None
    hex_value: str | None = None
    up: Any = None
    uv: Any = None
    be: Any = None
    bs: Any = None
    at: Any = None
    ed: Any = None


def _build_flag_payload(
    flag_details: Any,
    flags_byte: int | None,
    auth_byte_length: int | None = None,
) -> dict[str, Any]:
    if flag_details is None and flags_byte is None:
        return {}
    if flag_details is None and auth_byte_length is not None and auth_byte_length < 37:
        return {}

    facts = _FlagFacts(flags_byte=flags_byte)
    _read_flag_details(facts, flag_details)
    _read_flag_bits(facts)
    return _flag_payload(facts)


def _read_flag_details(facts: _FlagFacts, flag_details: Any) -> None:
    if not isinstance(flag_details, Mapping):
        return

    facts.bitfield = flag_details.get("bitfield")
    value = flag_details.get("value")
    try:
        facts.hex_value = f"{int(value):02x}".upper()
    except (TypeError, ValueError):
        facts.hex_value = None
    facts.up = flag_details.get("userPresent")
    facts.uv = flag_details.get("userVerified")
    facts.be = flag_details.get("backupEligible")
    facts.bs = flag_details.get("backupState")
    facts.at = flag_details.get("attestedCredentialData")
    facts.ed = flag_details.get("extensionData")
    if facts.flags_byte is None:
        try:
            facts.flags_byte = int(value)
        except (TypeError, ValueError):
            facts.flags_byte = None


def _read_flag_bits(facts: _FlagFacts) -> None:
    if facts.flags_byte is None:
        return

    if facts.bitfield is None:
        facts.bitfield = f"{facts.flags_byte:08b}"
    if facts.hex_value is None:
        facts.hex_value = f"{facts.flags_byte:02x}".upper()
    if facts.up is None:
        facts.up = bool(facts.flags_byte & 0x01)
    if facts.uv is None:
        facts.uv = bool(facts.flags_byte & 0x04)
    if facts.be is None:
        facts.be = bool(facts.flags_byte & 0x08)
    if facts.bs is None:
        facts.bs = bool(facts.flags_byte & 0x10)
    if facts.at is None:
        facts.at = bool(facts.flags_byte & 0x40)
    if facts.ed is None:
        facts.ed = bool(facts.flags_byte & 0x80)


def _flag_payload(facts: _FlagFacts) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if facts.bitfield:
        payload["bin"] = facts.bitfield.replace("0b", "")[-8:].zfill(8)
    if facts.hex_value:
        payload["hex"] = facts.hex_value
        payload["raw"] = facts.hex_value
    if facts.up is not None:
        payload["UP"] = bool(facts.up)
    if facts.uv is not None:
        payload["UV"] = bool(facts.uv)
    if facts.be is not None:
        payload["BE"] = bool(facts.be)
    if facts.bs is not None:
        payload["BS"] = bool(facts.bs)
    if facts.at is not None:
        payload["AT"] = bool(facts.at)
    if facts.ed is not None:
        payload["ED"] = bool(facts.ed)
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
        facts.aaguid_uuid = aaguid.guid(aaguid_bytes)
    if facts.credential_id_hex is None:
        facts.credential_id_hex = credential_bytes.hex()
    if facts.credential_id_length is None:
        facts.credential_id_length = f"{cred_length:04x}".upper()
    if public_key_bytes:
        facts.public_key_raw_hex = public_key_bytes.hex()


def _public_key_payload(facts: _CredentialFacts, fallback_alg: Any | None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if facts.cose_key is not None:
        payload["cose"] = make_json_safe(cose_display._convert_cose_key_for_display(facts.cose_key))
        alg_label = cose_display._resolve_cose_algorithm(facts.cose_key, fallback_alg)
    else:
        alg_label = cose_display._resolve_cose_algorithm({}, fallback_alg)
    if alg_label is not None:
        payload["alg"] = alg_label
    payload.update(cose_display._describe_cose_key(facts.cose_key))
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
