"""General and binary-focused encoder handlers."""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ...json_values import make_json_safe
from .. import values
from .binary_extract import (
    _determine_pem_label,
    _extract_generic_binary_payload,
    _format_pem_block,
)


def _prepare_encoder_response(
    base_type: str,
    data: Mapping[str, Any],
    *,
    qualifier: str | None = None,
    warnings: Sequence[str] | None = None,
) -> dict[str, Any]:
    type_label = base_type
    if qualifier:
        type_label = f"{base_type} ({qualifier})"

    safe_data = values.stringify_mapping_keys(make_json_safe(data))
    return {
        "success": True,
        "type": type_label,
        "data": safe_data,
        "malformed": list(warnings or ()),
    }


def _normalize_encoding_format(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Encoder format must be a string.")

    normalized = value.strip().lower()
    if not normalized:
        raise ValueError("Encoder format must be provided.")

    aliases = {
        "json": "json",
        "cbor": "cbor",
        "cbor (canonical)": "cbor",
        "cbor (ctap/webauthn data)": "ctap-webauthn",
        "json (binary)": "json",
        "der": "der",
        "pem": "pem",
        "cose": "cose",
        "edn": "edn",
        "cbor (edn)": "edn",
        "edn (exact bytes)": "edn",
    }

    if normalized in aliases:
        return aliases[normalized]

    raise ValueError(f"Unsupported encoder format: {value}")


def _encode_json_value(parsed: Any) -> dict[str, Any]:
    text = json.dumps(parsed, indent=2, ensure_ascii=False)
    data_bytes = text.encode("utf-8")
    payload = {
        "json": make_json_safe(parsed),
        "text": text,
        "binary": values.binary_summary(data_bytes, "json"),
    }
    return _prepare_encoder_response("JSON", payload, qualifier="encoded")


def _encode_binary_variant(
    parsed: Any,
    *,
    base_type: str,
    encoding: str,
    output_key: str,
    output_value: Callable[[dict[str, Any], bytes], Any],
    qualifier: str,
) -> dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = values.binary_summary(data_bytes, encoding)
    payload = {
        "binary": summary,
        output_key: output_value(summary, data_bytes),
    }
    return _prepare_encoder_response(base_type, payload, qualifier=qualifier)


def _encode_der_value(parsed: Any) -> dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="DER",
        encoding="der",
        output_key="derBase64",
        output_value=lambda summary, _data: summary["base64"],
        qualifier="encoded",
    )


def _encode_pem_value(parsed: Any) -> dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = values.binary_summary(data_bytes, "pem")
    label = _determine_pem_label(parsed)
    payload = {
        "binary": summary,
        "pem": _format_pem_block(summary["base64"], label),
    }
    return _prepare_encoder_response("PEM", payload, qualifier="encoded")
