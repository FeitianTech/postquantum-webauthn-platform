"""General and binary-focused encoder handlers."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from ...attestation import make_json_safe, serialize_attestation_certificate
from ..decode import (
    _binary_summary,
    _describe_authenticator_data_bytes,
    _hex_json_safe,
    _parse_attestation_object,
    _stringify_mapping_keys,
)
from .binary_extract import (
    _determine_pem_label,
    _extract_binary_input,
    _extract_generic_binary_payload,
    _format_pem_block,
)


def _prepare_encoder_response(
    base_type: str,
    data: Mapping[str, Any],
    *,
    qualifier: Optional[str] = None,
    warnings: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    type_label = base_type
    if qualifier:
        type_label = f"{base_type} ({qualifier})"

    safe_data = _stringify_mapping_keys(make_json_safe(data))
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
        "webauthn client data": "client-data",
        "clientdata": "client-data",
        "client data": "client-data",
        "authenticator data": "auth-data",
        "authdata": "auth-data",
        "attestation object": "attestation-object",
        "attestation": "attestation-object",
        "x.509 certificate": "x509",
        "x509": "x509",
        "publickeycredential": "public-key-credential",
        "public key credential": "public-key-credential",
        "der": "der",
        "pem": "pem",
        "cose": "cose",
    }

    if normalized in aliases:
        return aliases[normalized]

    raise ValueError(f"Unsupported encoder format: {value}")


def _encode_json_value(parsed: Any) -> Dict[str, Any]:
    text = json.dumps(parsed, indent=2, ensure_ascii=False)
    data_bytes = text.encode("utf-8")
    payload = {
        "json": make_json_safe(parsed),
        "text": text,
        "binary": _binary_summary(data_bytes, "json"),
    }
    return _prepare_encoder_response("JSON", payload, qualifier="encoded")


def _encode_public_key_credential(parsed: Any) -> Dict[str, Any]:
    if not isinstance(parsed, Mapping):
        raise ValueError("PublicKeyCredential encoding expects a JSON object.")

    text = json.dumps(parsed, indent=2, ensure_ascii=False)
    payload = {
        "credential": make_json_safe(parsed),
        "text": text,
        "binary": _binary_summary(text.encode("utf-8"), "json"),
    }
    return _prepare_encoder_response(
        "PublicKeyCredential", payload, qualifier="encoded"
    )


def _encode_client_data(parsed: Any) -> Dict[str, Any]:
    if not isinstance(parsed, Mapping):
        raise ValueError("WebAuthn client data must be provided as a JSON object.")

    compact = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
    data_bytes = compact.encode("utf-8")
    summary = _binary_summary(data_bytes, "json")
    summary["text"] = compact
    summary["json"] = make_json_safe(parsed)

    payload = {"clientDataJSON": summary}
    return _prepare_encoder_response(
        "WebAuthn client data", payload, qualifier="encoded"
    )


def _encode_authenticator_data(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_binary_input(parsed, "authenticatorData")
    details = _describe_authenticator_data_bytes(data_bytes)

    payload = {
        "authenticatorData": {
            "binary": _binary_summary(data_bytes, "binary"),
            "details": _stringify_mapping_keys(_hex_json_safe(details)),
        }
    }
    return _prepare_encoder_response(
        "Authenticator data", payload, qualifier="encoded"
    )


def _encode_attestation_object(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_binary_input(parsed, "attestationObject")
    decoded = _parse_attestation_object(data_bytes)
    payload = {
        "attestationObject": {
            "binary": _binary_summary(data_bytes, "cbor"),
            "details": _stringify_mapping_keys(_hex_json_safe(decoded)),
        }
    }
    return _prepare_encoder_response(
        "Attestation object", payload, qualifier="encoded"
    )


def _encode_x509_certificate(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_binary_input(parsed, "certificate")
    details = serialize_attestation_certificate(data_bytes)
    payload = {
        "certificate": {
            "binary": _binary_summary(data_bytes, "der"),
            "details": _stringify_mapping_keys(make_json_safe(details)),
        }
    }
    return _prepare_encoder_response("X.509 certificate", payload, qualifier="encoded")


def _encode_binary_variant(
    parsed: Any,
    *,
    base_type: str,
    encoding: str,
    output_key: str,
    output_value: Callable[[Dict[str, Any], bytes], Any],
    qualifier: str,
) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, encoding)
    payload = {
        "binary": summary,
        output_key: output_value(summary, data_bytes),
    }
    return _prepare_encoder_response(base_type, payload, qualifier=qualifier)


def _encode_hex_value(parsed: Any) -> Dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="Hex",
        encoding="hex",
        output_key="hex",
        output_value=lambda summary, _data: summary["hex"],
        qualifier="encoded",
    )


def _encode_base64_value(parsed: Any) -> Dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="Base64",
        encoding="base64",
        output_key="base64",
        output_value=lambda summary, _data: summary["base64"],
        qualifier="encoded",
    )


def _encode_base64url_value(parsed: Any) -> Dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="Base64URL",
        encoding="base64url",
        output_key="base64url",
        output_value=lambda summary, _data: summary["base64url"],
        qualifier="encoded",
    )


def _encode_binary_value(parsed: Any) -> Dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="Binary data",
        encoding="binary",
        output_key="bytes",
        output_value=lambda _summary, data: list(data),
        qualifier="raw bytes",
    )


def _encode_der_value(parsed: Any) -> Dict[str, Any]:
    return _encode_binary_variant(
        parsed,
        base_type="DER",
        encoding="der",
        output_key="derBase64",
        output_value=lambda summary, _data: summary["base64"],
        qualifier="encoded",
    )


def _encode_pem_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "pem")
    label = _determine_pem_label(parsed)
    payload = {
        "binary": summary,
        "pem": _format_pem_block(summary["base64"], label),
    }
    return _prepare_encoder_response("PEM", payload, qualifier="encoded")
