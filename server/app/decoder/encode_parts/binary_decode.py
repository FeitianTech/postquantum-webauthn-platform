"""Binary decoding helpers for encoder flows."""
from __future__ import annotations

import base64
import binascii
import re
import string
from typing import Any, Mapping, Optional, Sequence


def _decode_pem_text(
    pem_text: str,
    *,
    require_non_empty: bool = False,
) -> Optional[bytes]:
    has_markers = "-----BEGIN" in pem_text or "-----END" in pem_text
    if has_markers:
        body_lines = []
        for line in pem_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("-----"):
                continue
            body_lines.append(stripped)
        body = "".join(body_lines)
    else:
        body = pem_text

    body = "".join(re.findall(r"[A-Za-z0-9+/=]", body))
    if not body:
        return None

    padding = "=" * ((4 - len(body) % 4) % 4)
    try:
        decoded = base64.b64decode(body + padding, validate=True)
    except (ValueError, binascii.Error):
        return None

    if require_non_empty and not decoded:
        return None
    return decoded


def _require_bytes(value: Any, field_name: str) -> bytes:
    decoded = _maybe_decode_bytes(value)
    if decoded is None:
        raise ValueError(f"Unable to interpret {field_name} as binary data.")
    return decoded


def _maybe_decode_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        hex_candidate = candidate.replace(":", "")
        if len(hex_candidate) % 2 == 0 and hex_candidate and all(
            char in string.hexdigits for char in hex_candidate
        ):
            try:
                return bytes.fromhex(hex_candidate)
            except ValueError:
                pass

        cleaned = "".join(candidate.split())
        if cleaned:
            padding = (-len(cleaned)) % 4
            for decoder, encoder in (
                (base64.b64decode, base64.b64encode),
                (base64.urlsafe_b64decode, base64.urlsafe_b64encode),
            ):
                try:
                    decoded = decoder(cleaned + "=" * padding)
                except (ValueError, binascii.Error):
                    continue

                # Confirm the round-trip to avoid misclassifying plain text as base64.
                try:
                    reencoded = encoder(decoded).decode("ascii").rstrip("=")
                except Exception:  # pragma: no cover - defensive
                    continue
                if reencoded == cleaned.rstrip("="):
                    return decoded

    if isinstance(value, Mapping):
        for key in ("raw", "hex", "hexValue", "hexString"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                try:
                    return bytes.fromhex(entry.replace(":", ""))
                except ValueError:
                    continue

        for key in ("base64", "derBase64", "valueBase64"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                cleaned = "".join(entry.split())
                padding = (-len(cleaned)) % 4
                try:
                    return base64.b64decode(cleaned + "=" * padding)
                except (ValueError, binascii.Error):
                    continue

        entry = value.get("base64url")
        if isinstance(entry, str) and entry.strip():
            cleaned = "".join(entry.split())
            padding = (-len(cleaned)) % 4
            try:
                return base64.urlsafe_b64decode(cleaned + "=" * padding)
            except (ValueError, binascii.Error):
                pass

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
