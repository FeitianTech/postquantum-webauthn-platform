from __future__ import annotations

import math
import string
import uuid
from typing import Any, Dict, Mapping, MutableMapping, Optional

CRED_PROTECT_LABELS: Dict[Any, str] = {
    1: "userVerificationOptional",
    2: "userVerificationOptionalWithCredentialIDList",
    3: "userVerificationRequired",
    "userVerificationOptional": "userVerificationOptional",
    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationRequired": "userVerificationRequired",
}


def describe_cred_protect(value: Any) -> Any:
    """Return a human readable credProtect description when possible."""
    return CRED_PROTECT_LABELS.get(value, value)


def coerce_non_negative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        if math.isfinite(value) and value >= 0:
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = int(stripped, 10)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def normalize_aaguid_string(value: Any) -> Optional[str]:
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch in string.hexdigits)
        if len(cleaned) == 32:
            return cleaned.lower()
    return None


def coerce_aaguid_hex(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        hex_value = bytes(value).hex()
        return hex_value if len(hex_value) == 32 else None

    if isinstance(value, str):
        normalized = normalize_aaguid_string(value)
        if normalized and len(normalized) == 32:
            return normalized
        return None

    if isinstance(value, Mapping):
        for key in ("aaguid", "hex", "raw", "value", "guid"):
            candidate = coerce_aaguid_hex(value.get(key))
            if candidate:
                return candidate
        return None

    try:
        raw_bytes = bytes(value)
    except Exception:
        return None

    hex_value = raw_bytes.hex()
    if len(hex_value) != 32:
        return None
    return hex_value


def augment_aaguid_fields(container: MutableMapping[str, Any]) -> None:
    if not isinstance(container, MutableMapping):
        return

    raw_value = container.get("aaguid")
    aaguid_hex: Optional[str] = None

    if isinstance(raw_value, (bytes, bytearray, memoryview)):
        aaguid_hex = bytes(raw_value).hex()
    elif isinstance(raw_value, str):
        aaguid_hex = normalize_aaguid_string(raw_value)
    elif isinstance(raw_value, Mapping):
        for key in ("hex", "raw", "value"):
            candidate = raw_value.get(key)
            if isinstance(candidate, str):
                normalized = normalize_aaguid_string(candidate)
                if normalized:
                    aaguid_hex = normalized
                    break

    if aaguid_hex:
        container["aaguid"] = aaguid_hex
        container["aaguidHex"] = aaguid_hex
        container["aaguidRaw"] = aaguid_hex
        try:
            container["aaguidGuid"] = str(uuid.UUID(hex=aaguid_hex))
        except ValueError:
            container.pop("aaguidGuid", None)
    else:
        container.pop("aaguidHex", None)
        container.pop("aaguidGuid", None)
        container.pop("aaguidRaw", None)


def extract_min_pin_length(extension_results: Any) -> Optional[int]:
    if not isinstance(extension_results, Mapping):
        return None

    raw_value = extension_results.get("minPinLength")
    candidate = coerce_non_negative_int(raw_value)
    if candidate is not None:
        return candidate

    if isinstance(raw_value, Mapping):
        for key in ("minPinLength", "minimumPinLength", "value"):
            nested_candidate = coerce_non_negative_int(raw_value.get(key))
            if nested_candidate is not None:
                return nested_candidate

    return None


def summarize_authenticator_extensions(extensions: Mapping[str, Any]) -> Dict[str, Any]:
    """Augment authenticator extension outputs with human friendly metadata."""
    summary: Dict[str, Any] = {}
    for name, ext_value in extensions.items():
        summary[name] = ext_value
        if name == "credProtect":
            summary["credProtectLabel"] = describe_cred_protect(ext_value)
    return summary
