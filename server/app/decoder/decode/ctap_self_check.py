"""Whether a CTAP view gives back the bytes it was read from: the decoder's check of its own view.

The encoder writes a view back in CTAP2 canonical form, with ``ctap_message.rebuild``.
A message that was not in that form -- a head wider than its value needs, an
indefinite length, keys out of order, a repeated key -- or that the lenient
parser read past damage, has a view no encoder can turn back into its bytes:
the view is JSON, and cannot say how the bytes were laid out. The decoder
rebuilds each view it shows and compares; one that differs is marked in
``data.ctap.notRebuildable``, saying why, and the encoder refuses it by that
mark rather than write other bytes without a word. The item's EDN
(``data.edn``) is exact, and the encoder's EDN input gives the bytes back.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .. import ctap_message

# The findings that the input is not what the encoder writes.
_CAUSES = {"canonical", "malformed", "skipped"}
_SHOWN = 4


def check(
    message: str, view: Mapping[str, Any], framing: Mapping[str, Any], data: bytes, findings: Sequence[Mapping[str, Any]]
) -> str | None:
    """Why ``view`` does not give back ``data``; ``None`` when it does."""

    try:
        rebuilt: bytes | None = ctap_message.rebuild(message, view, framing)
        unreadable = ""
    except ValueError as exc:
        rebuilt, unreadable = None, str(exc)
    if rebuilt == data:
        return None
    causes = [f"{finding['code']} at offset {finding['offset']}" for finding in findings if finding.get("category") in _CAUSES]
    if causes:
        more = f", and {len(causes) - _SHOWN} more" if len(causes) > _SHOWN else ""
        return f"the input is not what the encoder writes, well-formed CTAP2 canonical CBOR: {', '.join(causes[:_SHOWN])}{more}"
    if rebuilt is None:
        return f"the view does not read back: {unreadable}"
    first = next((index for index, (a, b) in enumerate(zip(rebuilt, data)) if a != b), min(len(rebuilt), len(data)))
    return f"the view writes other bytes than the input from offset {first}"
