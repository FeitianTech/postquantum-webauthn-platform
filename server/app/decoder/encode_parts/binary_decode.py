"""Binary decoding helpers for encoder flows."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ... import encoding


def _decode_pem_text(
    pem_text: str,
    *,
    require_non_empty: bool = False,
) -> bytes | None:
    try:
        decoded = encoding.decode_pem_body(pem_text)
    except encoding.EncodingError:
        return None

    if require_non_empty and not decoded:
        return None
    return decoded


def _require_bytes(value: Any, field_name: str) -> bytes:
    decoded = _maybe_decode_bytes(value)
    if decoded is None:
        raise ValueError(f"Unable to interpret {field_name} as binary data.")
    return decoded


def _maybe_decode_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        decoded = encoding.try_decode_hex(candidate, allow_separators=True)
        if decoded is not None:
            return decoded

        # Strict decoding subsumes the round-trip check the open-coded version
        # needed to keep plain text from being misclassified as base64.
        for decoder in (encoding.try_decode_base64, encoding.try_decode_base64url):
            decoded = decoder(candidate)
            if decoded is not None:
                return decoded

    if isinstance(value, Mapping):
        for key in ("raw", "hex", "hexValue", "hexString"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                decoded = encoding.try_decode_hex(entry, allow_separators=True)
                if decoded is not None:
                    return decoded

        for key in ("base64", "derBase64", "valueBase64"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                decoded = encoding.try_decode_base64(entry)
                if decoded is not None:
                    return decoded

        entry = value.get("base64url")
        if isinstance(entry, str) and entry.strip():
            decoded = encoding.try_decode_base64url(entry)
            if decoded is not None:
                return decoded

        bytes_field = value.get("bytes")
        if isinstance(bytes_field, Sequence) and all(
            isinstance(item, int) and 0 <= item < 256 for item in bytes_field
        ):
            return bytes(bytes_field)

        pem_value = value.get("pem")
        if isinstance(pem_value, str) and pem_value.strip():
            decoded_pem = _decode_pem_text(pem_value.strip())
            if decoded_pem is not None:
                return decoded_pem

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if all(isinstance(item, int) and 0 <= item < 256 for item in value):
            return bytes(value)

    return None


def _require_certificate_bytes(entry: Any, index: int) -> bytes:
    decoded = _maybe_decode_bytes(entry)
    if decoded is not None:
        return decoded

    if isinstance(entry, Mapping):
        pem = entry.get("pem")
        if isinstance(pem, str) and pem.strip():
            decoded_pem = _decode_pem_text(pem.strip(), require_non_empty=True)
            if decoded_pem is not None:
                return decoded_pem
            raise ValueError("Unable to decode certificate PEM contents.")

    raise ValueError(f"Unable to recover certificate bytes for x5c[{index}].")
