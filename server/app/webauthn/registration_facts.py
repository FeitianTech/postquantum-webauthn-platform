"""What a verified registration's authenticator data and extension outputs say, one way for both tabs.

The flags in the order of their bits (``flags``), whether largeBlob did anything
(``large_blob_result``), a byte string's three spellings (``byte_forms``), the
AAGUID (``aaguid_values``, ``record_aaguid``, ``aaguid_block``), and authData's
rpIdHash beside the hash of the RP ID it should be (``rp_id_hash_report``,
``record_rp_id_hash``).
"""
from __future__ import annotations

import hashlib
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


def rp_id_hash_report(auth_data: Any, resolved_rp_id: str) -> dict[str, Any]:
    """authData's rpIdHash and the hash of the RP ID it should be, as bytes, hex and base64url."""

    rp_id_hash_hex = ""
    rp_id_hash_b64 = ""
    try:
        rp_id_hash_bytes = bytes(getattr(auth_data, "rp_id_hash", b""))
    except (TypeError, ValueError):
        rp_id_hash_bytes = b""
    else:
        rp_id_hash_hex = rp_id_hash_bytes.hex()
        rp_id_hash_b64 = encode_base64url(rp_id_hash_bytes)

    expected_rp_hash_bytes = hashlib.sha256((resolved_rp_id or "").encode("utf-8")).digest()
    return {
        "bytes": rp_id_hash_bytes,
        "hex": rp_id_hash_hex,
        "base64url": rp_id_hash_b64,
        "expectedBytes": expected_rp_hash_bytes,
        "expectedHex": expected_rp_hash_bytes.hex(),
        "expectedBase64url": encode_base64url(expected_rp_hash_bytes),
    }


def record_rp_id_hash(properties: dict[str, Any], report: Mapping[str, Any]) -> None:
    """Add the rpIdHash and the expected one to a stored credential's properties."""

    if report["hex"]:
        properties["rpIdHash"] = report["hex"]
    if report["base64url"]:
        properties["rpIdHashBase64"] = report["base64url"]
    properties["rpIdHashExpected"] = report["expectedHex"]
    properties["rpIdHashExpectedBase64"] = report["expectedBase64url"]
