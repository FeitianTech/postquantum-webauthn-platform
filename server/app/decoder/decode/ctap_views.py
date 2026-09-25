"""The views of a CTAP message: ``ctapDecoded``, and ``expandedJson`` beside it, one view built one way.

Every member of the map is shown as sent, labelled as ``ctap_message``
labels it, its value spelled by ``ctap_view`` from the parser's node, so the
encoder reads it back exactly. Two members are shown interpreted in place,
each carrying the bytes it was read from (``ctap_message``): authenticator data
(its fields as far as its flags describe them, ``raw`` and ``trailingBytesHex``)
and each x5c certificate of an attestation statement (``raw``, ``pem`` and the
certificate read, or why it would not read). Nothing is added: no member the
map did not hold, no wrapper around what it did.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .. import ctap_message, ctap_view
from . import response
from .ctap_auth_data import _format_auth_data_for_expanded_json


def view(message: str, node: Mapping[str, Any]) -> dict[str, Any]:
    """The members of the map ``node``, a ``message``, as the decoder shows them."""

    return ctap_view.labelled(
        node,
        lambda key_node: ctap_message.member_label(message, key_node),
        lambda entry: _member(message, entry["key"], entry["value"]),
    )


def _member(message: str, key_node: Mapping[str, Any], value_node: Mapping[str, Any]) -> Any:
    number = key_node.get("value") if key_node.get("majorType") in (0, 1) else None
    if (message, number) in ctap_message.AUTHENTICATOR_DATA and _whole_bytes(value_node):
        details, _trailing = _format_auth_data_for_expanded_json(bytes.fromhex(value_node["hex"]))
        return details
    if (message, number) == ctap_message.ATTESTATION_STATEMENT and value_node.get("majorType") == 5:
        return ctap_view.labelled(value_node, ctap_view.key_label, _statement_member)
    return ctap_view.spell(value_node)


def _statement_member(entry: Mapping[str, Any]) -> Any:
    key, value = entry["key"], entry["value"]
    if key.get("majorType") == 3 and key.get("value") == "x5c" and value.get("majorType") == 4:
        return [_certificate(item) for item in value.get("items") or []]
    return ctap_view.spell(value)


def _certificate(node: Mapping[str, Any]) -> Any:
    """An x5c entry: a certificate read, with its bytes; anything that is no byte string, spelled as sent."""

    if not _whole_bytes(node):
        return ctap_view.spell(node)
    shown = dict(response._convert_certificate_bytes(bytes.fromhex(node["hex"])))
    shown["raw"] = node["hex"]
    return shown


def _whole_bytes(node: Mapping[str, Any]) -> bool:
    return node.get("majorType") == 2 and not node.get("damaged") and not node.get("truncated") and "hex" in node
