"""CTAP messages in the decoder: the command or status byte, the views of each message, the payload read."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import (
    canonical,
    cbor_parser,
    ctap_classify,
    ctap_views,
    interpretations,
    key_collisions,
    pipeline,
)
from .cbor_parser import _structure_to_value
from .ctap_classify import _classify_ctap_payload
from .ctap_prefix import _extract_ctap_prefix, _is_padding_bytes, prefix_not_read
from .findings import _attach_findings, _trailing_findings
from .keys import hex_json_safe as _hex_json_safe
from .keys import stringify_mapping_keys as _stringify_mapping_keys

# What ``ctapDecoded`` calls the message each shape is.
MESSAGE_NAMES = {
    "make_credential_output": "makeCredentialResponse",
    "get_assertion_output": "getAssertionResponse",
    "get_info_output": "getInfoResponse",
    "make_credential_input": "makeCredentialRequest",
    "get_assertion_input": "getAssertionRequest",
}


def _try_decode_cbor(data: bytes, encoding: str, *, lenient: bool = False) -> dict[str, Any] | None:
    if not data:
        return None

    ctap_info, payload = _extract_ctap_prefix(data)
    ctap_details = dict(ctap_info) if ctap_info is not None else None

    if not payload:
        return _empty_payload(data, encoding, ctap_details)

    # One item, parsed strictly unless the caller asked for lenient parsing. A
    # payload that is not well-formed raises with its offset, counted from the
    # first input byte, prefix included.
    start = len(data) - len(payload)
    node, end, skipped = cbor_parser.decode_item(data, start, lenient=lenient)
    base_value = _structure_to_value(node)

    classification = _classify_ctap_payload(base_value, ctap_details)
    decoded_payload = _payload_views(node, base_value, classification)

    extra, located = interpretations.for_ctap(classification, base_value, node, data)
    findings = canonical.check(node, data) + key_collisions.check(node) + skipped + _trailing_findings(data, end) + located + prefix_not_read(data)
    findings += ctap_classify.shape_findings(base_value, ctap_details, classification)

    ctap_decoded = decoded_payload.get("ctapDecoded")
    message = next(iter(ctap_decoded)) if isinstance(ctap_decoded, Mapping) else None
    if ctap_details is not None or message is not None:
        decoded_payload["ctap"] = _framing(ctap_details, message, end - start, data[end:])

    result: dict[str, Any] = {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": pipeline._binary_summary(data, encoding),
        "decodeMode": "lenient" if lenient else "strict",
        "extraData": extra,
    }
    _attach_findings(result, findings)
    return result


def _empty_payload(data: bytes, encoding: str, ctap_details: dict[str, Any] | None) -> dict[str, Any]:
    """A CTAP command or status byte with nothing after it."""

    decoded_payload: dict[str, Any] = {
        "decodedValue": {"summary": "Empty CBOR payload", "byteLength": 0},
    }
    if ctap_details is not None:
        ctap_details["payloadLength"] = 0
        decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)
    return {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": pipeline._binary_summary(data, encoding),
    }


def _payload_views(node: Mapping[str, Any], base_value: Any, classification: str) -> dict[str, Any]:
    """``ctapDecoded`` and ``expandedJson`` for a CTAP message; ``decodedValue`` for anything else."""

    message = MESSAGE_NAMES.get(classification) if isinstance(base_value, Mapping) else None
    if message == "getInfoResponse":
        # What its members mean is beside it, in getInfoDecoded (interpretations.py).
        return {"ctapDecoded": {message: ctap_views.view(message, node)}}
    if message is not None:
        shown = ctap_views.view(message, node)
        return {"ctapDecoded": {message: shown}, "expandedJson": shown}
    return {"decodedValue": _stringify_mapping_keys(_hex_json_safe(base_value))}


def _framing(
    ctap_details: dict[str, Any] | None, message: str | None, payload_length: int, remaining: bytes
) -> dict[str, Any]:
    """``data.ctap``: the message's framing, all the encoder needs besides the view to rebuild the input.

    ``code`` is the command or status byte sent before the message, or null when
    none was; ``message`` names the CTAP message ``ctapDecoded`` shows;
    ``trailingBytesHex`` holds every byte after it, padding (all 0x00 or 0xff,
    counted in ``paddingBytes``) too.
    """

    framing = dict(ctap_details) if ctap_details is not None else {"code": None}
    if message is not None:
        framing["message"] = message
    framing["payloadLength"] = payload_length
    if remaining:
        framing["trailingBytesHex"] = remaining.hex()
        if _is_padding_bytes(remaining):
            framing["paddingBytes"] = len(remaining)
    return _stringify_mapping_keys(framing)
