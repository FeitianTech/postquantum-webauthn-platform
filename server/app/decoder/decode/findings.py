"""A decoder result's findings: the list the response carries, and what the input left over."""
from __future__ import annotations

from typing import Any

from .ctap_prefix import _is_padding_bytes

# What ``malformed`` lists: findings that the input is not well-formed CBOR --
# a step the lenient parser took ("skipped"), a structure inside the input that
# does not parse ("malformed"), bytes after the item ("trailing": RFC 8949
# appendix F counts "too much data") -- or not in CTAP2 canonical form
# ("canonical", duplicate keys included). Notes about the input or its reading
# (ambiguous input, JSON key collisions, the CTAP nesting limit, JSON duplicate
# keys, CTAP conformance) are findings, not "malformed".
MALFORMED_CATEGORIES = frozenset({"skipped", "malformed", "trailing", "canonical"})


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


# A path an answer keeps, one per finding, is at most this long: 64 levels of keys cut to 32
# characters would make each finding's path 2 KB, and an input can make thousands of findings.
MAX_PATH = 256


def kept_path(path: str) -> str:
    # Cut in its middle: the start says where the path starts from, the end what it names.
    if len(path) <= MAX_PATH:
        return path
    half = (MAX_PATH - 3) // 2
    return f"{path[:half]}...{path[-(MAX_PATH - 3 - half):]}"


def _attach_findings(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    # Every finding reaches the answer here, whichever reading or nested part made its path.
    findings = [
        {**finding, "path": kept_path(finding["path"])} if len(finding.get("path") or "") > MAX_PATH else finding
        for finding in findings
    ]
    # A finding in JSON has a path and no offset (None): it sorts first.
    ordered = sorted(findings, key=lambda finding: (finding.get("source", ""), _offset(finding)))
    result["findings"] = ordered
    malformed = [finding["message"] for finding in ordered if finding.get("category") in MALFORMED_CATEGORIES]
    if malformed:
        result["malformed"] = malformed


def _offset(finding: dict[str, Any]) -> int:
    offset = finding.get("offset")
    return offset if isinstance(offset, int) else -1
