"""The encoder's one path from the decoder's view of a CTAP message back to its bytes.

The view is ``ctapDecoded`` (``{message: members}``), or ``expandedJson`` beside
a framing that names its message; the framing is ``data.ctap``. The members are
read by ``ctap_message``, by the one spelling ``ctap_view`` gives them, and
written in CTAP2 canonical form: nothing is guessed, and what the view cannot
say is refused, naming where.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..cbor_canonical import _canonical_cbor_dumps, _canonicalize_cbor_structure
from ..ctap_message import read_members
from ..decode import _binary_summary, _hex_json_safe, _stringify_mapping_keys
from . import ctap_framing
from .handlers_basic import _prepare_encoder_response

# The messages whose views the encoder rebuilds.
REBUILT = (
    "makeCredentialRequest",
    "getAssertionRequest",
    "makeCredentialResponse",
    "getAssertionResponse",
    "getInfoResponse",
)


def one_message(ctap_decoded: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    """The one message a ``ctapDecoded`` names, and its members."""

    others = [key for key in ctap_decoded if key not in REBUILT]
    if others:
        raise ValueError(
            f"ctapDecoded.{others[0]} is not a CTAP message the encoder builds; it builds {', '.join(REBUILT)}."
        )
    if len(ctap_decoded) > 1:
        raise ValueError(f"ctapDecoded holds {len(ctap_decoded)} messages ({', '.join(ctap_decoded)}); give it one.")
    if not ctap_decoded:
        raise ValueError("ctapDecoded names no CTAP message to encode.")
    message, view = next(iter(ctap_decoded.items()))
    if not isinstance(view, Mapping):
        raise ValueError(f"ctapDecoded.{message} must be an object for encoding.")
    return message, view


def encode(parsed: Mapping[str, Any], base_type: str) -> dict[str, Any] | None:
    """The encoder's answer for a CTAP view in ``parsed``; ``None`` when ``parsed`` holds none."""

    framing_given = parsed.get("ctap") if isinstance(parsed.get("ctap"), Mapping) else None
    ctap_decoded, expanded = parsed.get("ctapDecoded"), parsed.get("expandedJson")
    if isinstance(ctap_decoded, Mapping):
        message, view = one_message(ctap_decoded)
        framing = ctap_framing.require(framing_given, "ctapDecoded")
        ctap_framing.check_message(framing, message)
    elif framing_given is not None and isinstance(expanded, Mapping):
        framing = ctap_framing.require(framing_given, "expandedJson")
        message, view = one_message({ctap_framing.message(framing, "expandedJson"): expanded})
    else:
        return None
    members = read_members(message, view, "ctapDecoded")
    payload = {
        "binary": _binary_summary(ctap_framing.frame(framing, _canonical_cbor_dumps(members)), "cbor"),
        "encodedValue": _stringify_mapping_keys(_hex_json_safe(_canonicalize_cbor_structure(members))),
        # The view as it was given, keys as written, so the answer can be pasted back.
        "ctapDecoded": {message: view},
        "ctap": dict(framing),
    }
    return _prepare_encoder_response(base_type, payload, qualifier=f"encoded {message}")
