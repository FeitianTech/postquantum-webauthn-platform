"""Simple-tab binary coercion helpers.

``_decode_base64url_bytes_impl`` and ``_extract_assertion_credential_id_impl``
used to be defined here *and* on the advanced side; they now live once, in
:mod:`server.app.routes.binary_helpers`. ``_select_first_impl`` stays: the
advanced module's same-named helper skips ``None`` values and this one does
not, so they are separate functions rather than copies.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ... import encoding
from ..binary_helpers import decode_binary_text


def _add_base64_padding(value: str) -> str:
    """Pad *value* to a multiple of four characters.

    Retained because ``simple.__all__`` exports it; the decoders no longer need
    it, since :mod:`server.app.encoding` normalises padding itself.
    """

    return value + "=" * (-len(value) % 4)


def _decode_binary_value(value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        if not value.strip():
            raise ValueError("empty string")
        try:
            return decode_binary_text(value)
        except encoding.EncodingError as exc:
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Iterable):
        try:
            return bytes(value)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid iterable value") from exc

    raise ValueError("unsupported binary value type")


def _select_first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    """Return the value of the first key in *keys* present in *mapping*.

    Unlike ``advanced.parsing_helpers_impl._select_first_impl``, a
    present-but-``None`` value is returned rather than skipped.
    """

    for key in keys:
        if key in mapping:
            return mapping[key]
    return None
