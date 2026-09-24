"""A decoder result's findings: the list the response carries, and what the input left over."""
from __future__ import annotations

from typing import Any

from .ctap_prefix import _is_padding_bytes


def _trailing_findings(data: bytes, end: int) -> list[dict[str, Any]]:
    """Report the bytes after the top-level item: never decoded, never dropped.

    All 0x00 (or 0xff) is what an unstripped HID report ends with, and is
    reported as such -- still reported.
    """

    remaining = data[end:]
    if not remaining:
        return []
    note = " (all 0x00/0xff: HID report padding?)" if _is_padding_bytes(remaining) else ""
    return [
        {
            "code": "trailing-bytes",
            "category": "trailing",
            "offset": end,
            "path": "$",
            "length": len(remaining),
            "hex": remaining.hex(),
            "message": f"Trailing {len(remaining)} byte(s) after CBOR payload{note}.",
        }
    ]


def _attach_findings(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    ordered = sorted(findings, key=lambda finding: (finding.get("source", ""), finding["offset"]))
    result["findings"] = ordered
    if ordered:
        result["malformed"] = [finding["message"] for finding in ordered]
