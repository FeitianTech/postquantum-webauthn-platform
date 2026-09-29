"""Binary extraction and PEM formatting helpers for encoder flows."""
from __future__ import annotations

import re
import textwrap
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from .binary_decode import _maybe_decode_bytes
from .typed_keys import with_cbor_keys


def _extract_generic_binary_payload(value: Any) -> bytes:
    queue: deque[Any] = deque([value])
    seen: set[int] = set()

    while queue:
        candidate = queue.popleft()
        decoded = _maybe_decode_bytes(candidate)
        if decoded is not None:
            return decoded

        if isinstance(candidate, Mapping):
            marker = id(candidate)
            if marker in seen:
                continue
            seen.add(marker)

            preferred_keys = (
                "value",
                "data",
                "raw",
                "binary",
                "bytes",
                "payload",
                "body",
                "der",
                "derBase64",
                "pem",
                "base64",
                "base64url",
            )
            for key in preferred_keys:
                if key in candidate:
                    queue.append(candidate[key])

            for entry in candidate.values():
                if isinstance(entry, (Mapping, Sequence)) and not isinstance(
                    entry, (str, bytes, bytearray)
                ):
                    queue.append(entry)
        elif isinstance(candidate, Sequence) and not isinstance(
            candidate, (str, bytes, bytearray)
        ):
            queue.extend(candidate)

    raise ValueError("Unable to extract binary payload for encoding.")


def _determine_pem_label(value: Any) -> str:
    if isinstance(value, Mapping):
        for key in ("pemLabel", "label"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                return entry

        binary_section = value.get("binary")
        if isinstance(binary_section, Mapping):
            encoding_label = binary_section.get("encoding")
            if isinstance(encoding_label, str) and encoding_label.strip():
                return encoding_label

    return "DATA"


def _format_pem_block(base64_body: str, label: str) -> str:
    normalized_label = _normalize_pem_label(label)
    wrapped = "\n".join(textwrap.wrap(base64_body, 64)) if base64_body else ""
    return f"-----BEGIN {normalized_label}-----\n{wrapped}\n-----END {normalized_label}-----"


def _normalize_pem_label(label: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]+", " ", label).strip()
    if not sanitized:
        return "DATA"
    compact = re.sub(r"\s+", " ", sanitized)
    return compact.replace(" ", "_").upper()


def _restore_generic_structure(value: Any) -> Any:
    # Keys are read as the decoder wrote them: a typed spelling is the key it names.
    return with_cbor_keys(value)
