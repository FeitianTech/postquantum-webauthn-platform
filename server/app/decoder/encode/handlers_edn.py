"""EDN input: the bytes an extended diagnostic notation text notates, exactly.

Not canonicalised: map order, duplicate keys, head widths, indefinite lengths
and float widths are the text's (``decoder/edn``). The decoder's ``data.edn``
encodes back to the item it was decoded from.
"""
from __future__ import annotations

from typing import Any

from .. import edn
from ..decode import _binary_summary
from .handlers_basic import _prepare_encoder_response


def _encode_edn_value(text: str) -> dict[str, Any]:
    data = edn.encode(text)
    return _prepare_encoder_response("EDN", {"binary": _binary_summary(data, "cbor")}, qualifier="encoded")
