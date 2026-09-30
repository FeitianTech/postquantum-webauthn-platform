"""What a verified registration's authenticator data and extension outputs say, one way for both tabs.

The flags in the order of their bits (``flags``), whether largeBlob did anything
(``large_blob_result``), a byte string's three spellings (``byte_forms``), and
the AAGUID (``aaguid_values``, ``record_aaguid``, ``aaguid_block``).
"""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from ..encoding import encode_base64, encode_base64url

# authData's flags, in the order of their bits (WebAuthn L3 section 6.1).
FLAG_NAMES = ("UP", "UV", "BE", "BS", "AT", "ED")


def flags(auth_data: Any) -> dict[str, bool]:
    flags_value = getattr(auth_data, "flags", 0)
    return {flag: bool(flags_value & getattr(auth_data.FLAG, flag, 0)) for flag in FLAG_NAMES}


def large_blob_result(client_extension_results: Any) -> bool:
    """Whether the largeBlob output says the authenticator supported, wrote or read a blob."""

    if not isinstance(client_extension_results, Mapping) or "largeBlob" not in client_extension_results:
        return False
    large_blob_value = client_extension_results.get("largeBlob")
    if isinstance(large_blob_value, Mapping):
        return bool(
            large_blob_value.get("supported")
            or large_blob_value.get("written")
            or large_blob_value.get("blob")
            or large_blob_value.get("result")
        )
    return bool(large_blob_value)


def byte_forms(value: bytes) -> dict[str, str]:
    """``value`` as base64, base64url and hex."""

    return {
        "base64": encode_base64(value),
        "base64url": encode_base64url(value),
        "hex": value.hex(),
    }


def aaguid_values(credential_data: Any) -> tuple[bytes | None, str | None, str | None]:
    """The AAGUID's bytes, hex and GUID spelling; hex and GUID only for 16 bytes."""

    aaguid_hex = None
    aaguid_guid = None
    aaguid_bytes: bytes | None = None
    aaguid_value = getattr(credential_data, "aaguid", None)
    if aaguid_value is not None:
        try:
            aaguid_bytes = bytes(aaguid_value)
        except (TypeError, ValueError):
            aaguid_bytes = None
        if aaguid_bytes is not None and len(aaguid_bytes) == 16:
            aaguid_hex = aaguid_bytes.hex()
            try:
                aaguid_guid = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                aaguid_guid = None
    return aaguid_bytes, aaguid_hex, aaguid_guid


def record_aaguid(properties: dict[str, Any], aaguid_hex: str | None, aaguid_guid: str | None) -> None:
    """Add the AAGUID to a stored credential's properties."""

    if aaguid_hex:
        properties["aaguid"] = aaguid_hex
        properties["aaguidHex"] = aaguid_hex
    if aaguid_guid:
        properties["aaguidGuid"] = aaguid_guid


def aaguid_block(aaguid_hex: str | None, aaguid_guid: str | None) -> dict[str, Any]:
    """The AAGUID as the relying party's view shows it."""

    return {"raw": aaguid_hex, "guid": aaguid_guid}
