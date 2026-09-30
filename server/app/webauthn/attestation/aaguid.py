from __future__ import annotations

import math
import string
import uuid
from collections.abc import Mapping, MutableMapping
from typing import Any

from fido2.ctap2.extensions import CredProtectExtension

_CRED_PROTECT_POLICIES = tuple(CredProtectExtension.POLICY)
# WebAuthn's spelling, which a request may also use, of fido2's "...CredentialIDList".
_OPTIONAL_WITH_LIST_ALIAS = "userVerificationOptionalWithCredentialIdList"


def describe_cred_protect(value: Any) -> Any:
    """A credProtect policy's name, for its CTAP number (1-3) or a name; anything else as given."""

    if isinstance(value, int) and 1 <= value <= len(_CRED_PROTECT_POLICIES):
        return _CRED_PROTECT_POLICIES[value - 1].value
    if value == _OPTIONAL_WITH_LIST_ALIAS:
        return CredProtectExtension.POLICY.OPTIONAL_WITH_LIST.value
    return value


def coerce_non_negative_int(value: Any) -> int | None:
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


def normalize_aaguid_string(value: Any) -> str | None:
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch in string.hexdigits)
        if len(cleaned) == 32:
            return cleaned.lower()
    return None


def augment_aaguid_fields(container: MutableMapping[str, Any]) -> None:
    if not isinstance(container, MutableMapping):
        return

    raw_value = container.get("aaguid")
    aaguid_hex: str | None = None

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


def extract_min_pin_length(extension_results: Any) -> int | None:
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


def summarize_authenticator_extensions(extensions: Mapping[str, Any]) -> dict[str, Any]:
    """Augment authenticator extension outputs with human friendly metadata."""
    summary: dict[str, Any] = {}
    for name, ext_value in extensions.items():
        summary[name] = ext_value
        if name == "credProtect":
            summary["credProtectLabel"] = describe_cred_protect(ext_value)
    return summary
