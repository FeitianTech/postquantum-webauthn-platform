"""The encoder's entry: a value in one of the Codec's formats, as the answer ``/api/codec`` gives."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

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


def encode_payload_text(value: str, target_format: str) -> dict[str, Any]:
    """Encode ``value`` into the requested ``target_format``."""

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Encoder input is empty.")

    canonical = _normalize_encoding_format(target_format)
    if canonical == "edn":
        # EDN is not JSON: its text is the item, read by decoder/edn -- as sent,
        # so that the offset a refusal names counts the text's leading blank space.
        return _encode_edn_value(value)

    try:
        parsed, repeated = read_json(trimmed)
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

    handler = _ENCODING_HANDLERS.get(canonical)
    if handler is None:
        raise ValueError(f"Unsupported encoder format: {target_format}")

    # Keys are shown back as they were written; the CBOR key each spells is read where it is encoded.
    return handler(as_written(parsed))


_ENCODING_HANDLERS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "json": _encode_json_value,
    "cbor": _encode_cbor_value,
    "ctap-webauthn": _encode_ctap_webauthn_value,
    "der": _encode_der_value,
    "pem": _encode_pem_value,
    "cose": _encode_cose_value,
}
