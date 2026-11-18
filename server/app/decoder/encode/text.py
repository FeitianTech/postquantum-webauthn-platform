"""The encoder's entry: a value in one of the Codec's formats, as the answer ``/api/codec`` gives."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .. import item_budget
from ..decode import json_input
from ..decode.json_input import read as read_json
from ..decode.json_keys import as_written
from .handlers_basic import (
    _encode_der_value,
    _encode_json_value,
    _encode_pem_value,
    _normalize_encoding_format,
)
from .handlers_cbor import (
    _encode_cbor_value,
    _encode_cose_value,
    _encode_ctap_webauthn_value,
)
from .handlers_edn import _encode_edn_value


def encode_payload_text(
    value: str, target_format: str, *, max_items: int = item_budget.DEFAULT_MAX_ITEMS
) -> dict[str, Any]:
    """Encode ``value`` into the requested ``target_format``.

    What it reads, the JSON or EDN and the CBOR a typed key spells, counts
    against one budget of ``max_items`` (``item_budget``): past it, the input is
    refused with ``ItemLimitError``.
    """

    with item_budget.limit(max_items):
        return _encode(value, target_format)


def _encode(value: str, target_format: str) -> dict[str, Any]:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Encoder input is empty.")

    canonical = _normalize_encoding_format(target_format)
    if canonical == "edn":
        # EDN is not JSON: its text is the item, read by decoder/edn -- as sent,
        # so that the offset a refusal names counts the text's leading blank space.
        return _encode_edn_value(value)

    try:
        parsed, repeated = _read_json_value(value, trimmed)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive guard
        raise ValueError(
            "Encoder expects a JSON document describing the value to encode."
        ) from exc
    if repeated:
        # json.loads would keep one of the values: refuse rather than drop one.
        first = repeated[0]
        raise ValueError(
            f"The JSON repeats the key {json.dumps(first['key'], ensure_ascii=False)} at {first['path']}, "
            "and encoding it would drop a value. Remove one, or write the item in EDN (format \"EDN\"), "
            "which can repeat a key."
        )

    # _normalize_encoding_format refused any format that has no handler.
    handler = _ENCODING_HANDLERS[canonical]

    # Keys are shown back as they were written; the CBOR key each spells is read where it is encoded.
    return handler(as_written(parsed))


class JsonRefused(ValueError):
    """JSON the encoder takes no item from: ``NaN``, ``Infinity`` or ``-Infinity``, or a number no
    double holds. ``offset`` and ``path`` say where, as the decoder's refusals do."""

    def __init__(self, message: str, offset: int, path: str) -> None:
        super().__init__(message)
        self.offset, self.path = offset, path


def _read_json_value(value: str, trimmed: str) -> tuple[Any, list[dict[str, Any]]]:
    """``trimmed`` read as JSON, its offsets counted in ``value`` as sent (its leading blank space
    too, as the decoder counts them), and what it cannot take refused in the encoder's words: it
    has no lenient reading, and EDN writes NaN and the infinities."""

    try:
        return read_json(trimmed, base=len(value) - len(value.lstrip()))
    except json_input.JsonRangeError as exc:
        raise JsonRefused(
            f"Number out of range at offset {exc.offset} ({exc.path}): {exc.reason}, the widest float CBOR "
            "has.",
            exc.offset,
            exc.path,
        ) from None
    except json_input.JsonConstantError as exc:
        raise JsonRefused(
            f"Not JSON at offset {exc.offset} ({exc.path}): {exc.reason}. Write the item in EDN "
            '(format "EDN"), which writes NaN, Infinity and -Infinity.',
            exc.offset,
            exc.path,
        ) from None


_ENCODING_HANDLERS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "json": _encode_json_value,
    "cbor": _encode_cbor_value,
    "ctap-webauthn": _encode_ctap_webauthn_value,
    "der": _encode_der_value,
    "pem": _encode_pem_value,
    "cose": _encode_cose_value,
}
