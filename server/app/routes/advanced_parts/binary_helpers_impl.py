from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping, Optional


def _decode_client_binary_impl(_advanced_module: Any, value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError("empty binary value")

        for decoder in (
            lambda candidate: base64.urlsafe_b64decode(
                candidate + "=" * ((4 - len(candidate) % 4) % 4)
            ),
            lambda candidate: base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4)),
        ):
            try:
                return decoder(stripped)
            except (ValueError, TypeError, binascii.Error):
                continue

        try:
            return bytes.fromhex(stripped)
        except ValueError as exc:
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Mapping):
        if "$hex" in value or "hex" in value:
            hex_candidate = value.get("$hex")
            if hex_candidate is None:
                hex_candidate = value.get("hex")

            if isinstance(hex_candidate, str):
                stripped = hex_candidate.strip()
                if not stripped:
                    raise ValueError("empty binary value")
                try:
                    return bytes.fromhex(stripped)
                except ValueError as exc:
                    raise ValueError("invalid binary value") from exc

            return _decode_client_binary_impl(_advanced_module, hex_candidate)

        if "$base64url" in value or "base64url" in value:
            b64u_candidate = value.get("$base64url")
            if b64u_candidate is None:
                b64u_candidate = value.get("base64url")

            if isinstance(b64u_candidate, str):
                stripped = b64u_candidate.strip()
                if not stripped:
                    raise ValueError("empty binary value")
                if not re.fullmatch(r"[A-Za-z0-9_-]+", stripped):
                    raise ValueError("invalid binary value")
                try:
                    padding = "=" * ((4 - len(stripped) % 4) % 4)
                    return base64.urlsafe_b64decode(stripped + padding)
                except (ValueError, TypeError, binascii.Error) as exc:
                    raise ValueError("invalid binary value") from exc

            return _decode_client_binary_impl(_advanced_module, b64u_candidate)

        if "$base64" in value or "base64" in value:
            b64_candidate = value.get("$base64")
            if b64_candidate is None:
                b64_candidate = value.get("base64")

            if isinstance(b64_candidate, str):
                stripped = b64_candidate.strip()
                if not stripped:
                    raise ValueError("empty binary value")
                try:
                    padding = "=" * ((4 - len(stripped) % 4) % 4)
                    return base64.b64decode(stripped + padding)
                except (ValueError, TypeError, binascii.Error) as exc:
                    raise ValueError("invalid binary value") from exc

            return _decode_client_binary_impl(_advanced_module, b64_candidate)

    raise ValueError("unsupported binary value type")


def _decode_base64url_impl(_advanced_module: Any, data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _decode_base64url_bytes_impl(advanced_module: Any, value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return advanced_module._decode_base64url(value)
        except Exception:
            return b""
    return b""


def _extract_assertion_credential_id_impl(
    advanced_module: Any,
    response: Mapping[str, Any],
) -> Optional[bytes]:
    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        try:
            return advanced_module._decode_base64url(raw_id)
        except (ValueError, TypeError):
            return None

    return None


def _extract_binary_value_impl(_advanced_module: Any, value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "$hex" in value:
            return bytes.fromhex(value["$hex"])
        if "$base64" in value:
            encoded = value["$base64"]
            if not isinstance(encoded, str):
                return value
            padding = "=" * ((4 - len(encoded) % 4) % 4)
            return base64.b64decode(encoded + padding)
        if "$base64url" in value:
            encoded = value["$base64url"]
            if not isinstance(encoded, str):
                return value
            padding = "=" * ((4 - len(encoded) % 4) % 4)
            return base64.urlsafe_b64decode(encoded + padding)
    return value


def _encode_base64url_impl(_advanced_module: Any, data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
