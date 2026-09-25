"""Where a map read as a CTAP message does not conform: a key that is not an integer.

CTAP 2.2 section 6 numbers the members of each command's parameters and each
response with integer keys. A map the decoder reads as a makeCredential or
getAssertion request or response may still hold a text, byte-string or other
key, and so may a getInfo response; its view shows it, with its type, and this
reports it where it is.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .cbor_parser import _diagnostic_key

_KINDS = {
    "make_credential_input": "makeCredential request",
    "get_assertion_input": "getAssertion request",
    "make_credential_output": "makeCredential response",
    "get_assertion_output": "getAssertion response",
    "get_info_output": "getInfo response",
}


def non_integer_keys(classification: str, node: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One ``ctap-non-integer-key`` finding per top-level key of ``node`` that is not an integer."""

    kind = _KINDS.get(classification)
    if kind is None or node.get("majorType") != 5:
        return []
    findings: list[dict[str, Any]] = []
    for entry in node.get("entries") or []:
        key = entry.get("key")
        if not isinstance(key, Mapping) or key.get("majorType") in (0, 1) or key.get("type") == "invalid":
            continue
        findings.append(
            {
                "code": "ctap-non-integer-key",
                "category": "ctap",
                "offset": key["offset"],
                "path": entry.get("path") or "$",
                "message": (
                    f"map key {_diagnostic_key(key)} is not an integer: CTAP 2.2 section 6 numbers the "
                    f"members of a {kind} with integer keys, so this map is not a conformant CTAP message; "
                    "its view shows the key with its type"
                ),
            }
        )
    return findings
