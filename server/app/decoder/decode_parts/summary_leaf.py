"""Summary rendering leaf helpers for decoder output formatting."""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .binary_extract import _convert_cose_key_for_display, _resolve_cose_algorithm


def _append_simple_field(lines: List[str], label: str, value: Optional[Any], default: str = "(none)") -> None:
    if value is None:
        lines.append(f"{label}:\t{default}")
    else:
        lines.append(f"{label}:\t{value}")


def _append_multiline_field(
    lines: List[str],
    label: str,
    content_lines: Iterable[str],
    *,
    indent_str: str = "",
    default: str = "(none)",
    force_multiline: bool = False,
) -> None:
    filtered = [line for line in content_lines if line is not None]
    if not filtered:
        lines.append(f"{label}:\t{default}")
        return
    if len(filtered) == 1 and not force_multiline:
        lines.append(f"{label}:\t{filtered[0]}")
        return
    lines.append(f"{label}:\t")
    prefix = indent_str
    for line in filtered:
        lines.append(f"{prefix}{line}")


def _format_json_block(value: Any) -> List[str]:
    if value is None:
        return []
    try:
        return json.dumps(value, indent=2, sort_keys=False).splitlines()
    except (TypeError, ValueError):
        return [str(value)]


def _format_boolean(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and value in (0, 1):
        return "true" if bool(value) else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered
    return None


def _format_counter_value(counter: Any) -> Optional[str]:
    try:
        count = int(counter)
    except (TypeError, ValueError):
        return None
    if count < 0:
        return str(count)
    return f"0x{count:08x}={count}"


def _format_flag_line(flags: Any) -> Optional[str]:
    if not isinstance(flags, Mapping):
        return None
    try:
        value = int(flags.get("value"))
    except (TypeError, ValueError):
        return None
    bitfield = flags.get("bitfield")
    if not isinstance(bitfield, str) or not bitfield.startswith("0b"):
        bitfield = f"0b{value:08b}"
    components = [
        f"UP:{1 if flags.get('userPresent') else 0}",
        f"UV:{1 if flags.get('userVerified') else 0}",
        f"BE:{1 if flags.get('backupEligibility') else 0}",
        f"BS:{1 if flags.get('backupState') else 0}",
        f"AT:{1 if flags.get('attestedCredentialDataIncluded') else 0}",
        f"ED:{1 if flags.get('extensionDataIncluded') else 0}",
    ]
    return f"0x{value:02x}={bitfield}= {' '.join(components)}"


def _build_authenticator_data_lines(
    auth_bytes: Optional[bytes], auth_details: Optional[Mapping[str, Any]]
) -> List[str]:
    if auth_bytes:
        rp = auth_bytes[:32].hex()
        lines = [rp]
        if len(auth_bytes) > 32:
            lines.append(auth_bytes[32:33].hex())
        if len(auth_bytes) > 33:
            lines.append(auth_bytes[33:37].hex())
        if len(auth_bytes) > 37:
            remainder = auth_bytes[37:].hex()
            if remainder:
                lines.append(remainder)
        return lines

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
            if isinstance(rp_hex, str) and rp_hex:
                return [rp_hex]

    return []


def _parse_attested_data(auth_bytes: Optional[bytes]) -> Optional[Dict[str, bytes]]:
    if not auth_bytes or len(auth_bytes) <= 37:
        return None
    remainder = auth_bytes[37:]
    if len(remainder) < 18:
        return {"raw": remainder}
    aaguid = remainder[:16]
    length_bytes = remainder[16:18]
    credential_length = int.from_bytes(length_bytes, "big")
    credential_section = remainder[18:]
    if len(credential_section) < credential_length:
        credential_id = credential_section
        public_key = b""
    else:
        credential_id = credential_section[:credential_length]
        public_key = credential_section[credential_length:]
    return {
        "aaguid": aaguid,
        "length_bytes": length_bytes,
        "credential_id": credential_id,
        "public_key": public_key,
    }


def _collect_attested_info(
    attested: Mapping[str, Any], auth_bytes: Optional[bytes], fallback_alg: Optional[Any] = None
) -> Dict[str, Any]:
    parsed = _parse_attested_data(auth_bytes)
    credential_lines: List[str] = []
    credential_id_hex: Optional[str] = None
    aaguid_lines: List[str] = []

    if parsed and "aaguid" in parsed and isinstance(parsed["aaguid"], bytes):
        credential_lines.append(parsed["aaguid"].hex())
        aaguid_hex = parsed["aaguid"].hex()
    else:
        aaguid_hex = attested.get("aaguidHex") if isinstance(attested, Mapping) else None
        if isinstance(aaguid_hex, str):
            credential_lines.append(aaguid_hex)

    aaguid_display = attested.get("aaguid") if isinstance(attested, Mapping) else None
    if isinstance(aaguid_display, str) and aaguid_display:
        aaguid_lines.extend(filter(None, [aaguid_hex, aaguid_display]))
    elif aaguid_hex:
        aaguid_lines.append(aaguid_hex)

    if parsed and "length_bytes" in parsed and isinstance(parsed["length_bytes"], bytes):
        credential_lines.append(parsed["length_bytes"].hex())
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            length = credential.get("length")
            if isinstance(length, int):
                credential_lines.append(length.to_bytes(2, "big").hex())

    if parsed and "credential_id" in parsed and isinstance(parsed["credential_id"], bytes):
        credential_id_hex = parsed["credential_id"].hex()
        credential_lines.append(credential_id_hex)
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            credential_id_hex = credential.get("hex")
            if isinstance(credential_id_hex, str):
                credential_lines.append(credential_id_hex)

    if parsed and "public_key" in parsed and isinstance(parsed["public_key"], bytes):
        public_key_bytes = parsed["public_key"]
        if public_key_bytes:
            credential_lines.append(public_key_bytes.hex())

    public_key = attested.get("publicKey") if isinstance(attested, Mapping) else None
    algorithm_label = _resolve_cose_algorithm(public_key, fallback_alg)
    public_key_lines = _format_json_block(_convert_cose_key_for_display(public_key))

    info = {
        "credential_lines": credential_lines,
        "aaguid_lines": aaguid_lines or ([aaguid_hex] if aaguid_hex else []),
        "credential_id": credential_id_hex,
        "algorithm": algorithm_label,
        "public_key_lines": public_key_lines,
    }

    has_content = any(
        bool(info.get(key)) for key in ("credential_lines", "aaguid_lines", "credential_id", "public_key_lines")
    )
    return info if has_content else {}
