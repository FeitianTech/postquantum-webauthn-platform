"""Findings about what is inside an authenticator data byte string.

Authenticator data (WebAuthn L3 section 6.1) is a byte string with a 37-byte
header, then the attested credential data its AT flag announces and the
extensions its ED flag announces (section 6.5.1). The credential public key and
the extensions are CBOR, and get the same canonical-form check as the message
around them. Bytes after those belong to nothing; they are reported here, never
decoded and never dropped.

Offsets count from the start of the decoder input, like every other finding.
Paths continue the path of the authData byte string.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fido2.webauthn import AuthenticatorData

from .. import values
from . import canonical, key_collisions, key_equivalence
from .cbor_parser import _CborDecodingError, _structure_to_value, decode_item

_HEADER_LENGTH = 37


def for_member(root: Mapping[str, Any], data: bytes, keys: Sequence[Any]) -> list[dict[str, Any]]:
    """Check the authData held under the first of ``keys`` in the map ``root``.

    Its callers ask only for a member the decoded value holds as a byte string
    (the classification of a CTAP response, ``attestation_object.read``), and
    ``member_node`` finds the member the decoded value holds.
    """

    node = member_node(root, keys)
    if node.get("indefinite"):
        # Chunked: its bytes are not contiguous in the input, so nothing inside it
        # has an input offset of its own; each finding points at the string.
        chunks = b"".join(bytes.fromhex(chunk["hex"]) for chunk in node.get("chunks") or [])
        return [
            {**finding, "message": f"{finding['message']} (inside an indefinite-length byte string)"}
            for finding in canonical.pin_to(check(chunks, 0, node["path"]), node["offset"])
        ]
    start = node["end"] - node["length"]
    return check(data[start : node["end"]], start, node["path"])


def check(auth_data: bytes, base_offset: int, path: str) -> list[dict[str, Any]]:
    """Check the CBOR items in ``auth_data`` and report bytes after them."""

    findings: list[dict[str, Any]] = []
    items, offset = embedded_items(auth_data)
    for name, node in items:
        structure = canonical.check(node, auth_data) + key_collisions.check(node)
        findings += canonical.relocate(structure, base_offset, f"{path}<{name}>")
    if offset is None:
        # Where the embedded CBOR stops being well-formed, the decoded view says so.
        return findings

    remaining = auth_data[offset:]
    if remaining:
        findings.append(
            {
                "code": "authdata-trailing-bytes",
                "category": "trailing",
                "offset": base_offset + offset,
                "path": path,
                "length": len(remaining),
                "hex": remaining.hex(),
                "message": (
                    f"{len(remaining)} byte(s) inside authData after what its flags "
                    "(AT, ED) account for"
                ),
            }
        )
    return findings


def extensions(auth_data: bytes) -> Any:
    """The extensions ``auth_data`` carries under its ED flag, or ``values.MISSING``."""

    items, _end = embedded_items(auth_data)
    for name, node in items:
        if name == "extensions":
            return _structure_to_value(node)
    return values.MISSING


def embedded_items(auth_data: bytes) -> tuple[list[tuple[str, dict[str, Any]]], int | None]:
    """The CBOR items the flags announce, and where they end (``None``: unreadable)."""

    items: list[tuple[str, dict[str, Any]]] = []
    if len(auth_data) < _HEADER_LENGTH:
        return items, None
    flags = auth_data[32]
    offset = _HEADER_LENGTH
    try:
        if flags & AuthenticatorData.FLAG.AT:
            if len(auth_data) - offset < 18:
                return items, None
            offset += 18 + int.from_bytes(auth_data[offset + 16 : offset + 18], "big")
            if offset > len(auth_data):
                return items, None
            node, offset, _ = decode_item(auth_data, offset)
            items.append(("credentialPublicKey", node))
        if flags & AuthenticatorData.FLAG.ED:
            node, offset, _ = decode_item(auth_data, offset)
            items.append(("extensions", node))
    except _CborDecodingError:
        return items, None
    return items, offset


def member_node(root: Mapping[str, Any], keys: Sequence[Any]) -> Mapping[str, Any] | None:
    """The value node under the first of ``keys`` in the map node ``root``, with its path."""

    if not isinstance(root, Mapping) or root.get("majorType") != 5:
        return None
    by_key: dict[Any, Mapping[str, Any]] = {}
    for entry in root.get("entries") or []:
        # Keyed as the decoded value keys them: a damaged or non-UTF-8 text key
        # is no "authData", whatever the lenient parser kept of it. The decoded
        # value keeps the later of two duplicate keys; so does this.
        by_key[key_equivalence.identity(entry["key"])] = {**entry["value"], "path": entry.get("path")}
    for key in keys:
        node = by_key.get(values.key_identity(key))
        if node is not None:
            return node
    return None
