"""Top-level decode pipeline helpers."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography import x509

from fido2.utils import ByteBuffer

from ...attestation import make_json_safe, serialize_attestation_certificate
from ...encoding import EncodingError, SniffResult, sniff, try_decode_base64
from . import cbor_runtime, details_runtime, result_runtime

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def _decode_json_object(value: Any, raw_text: str | None = None) -> dict[str, Any]:
    if isinstance(value, Mapping) and details_runtime._is_public_key_credential(value):
        return _decode_public_key_credential(value, raw_text=raw_text)

    if isinstance(value, Mapping) and details_runtime._is_client_data_dict(value):
        details = details_runtime._build_client_data_details(value, raw_text=raw_text)
        return {
            "format": "WebAuthn client data (JSON)",
            "inputEncoding": "json",
            "decoded": details,
        }

    return {
        "format": "JSON",
        "inputEncoding": "json",
        "decoded": value,
    }


def _decode_public_key_credential(
    credential: Mapping[str, Any], raw_text: str | None = None
) -> dict[str, Any]:
    response = credential.get("response")
    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}

    response_details: dict[str, Any] = {
        key: value
        for key, value in response_mapping.items()
        if key
        not in {"attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle"}
    }

    decoded: dict[str, Any] = {
        "id": credential.get("id"),
        "type": credential.get("type"),
    }

    authenticator_attachment = credential.get("authenticatorAttachment")
    if authenticator_attachment is not None:
        decoded["authenticatorAttachment"] = authenticator_attachment

    transports = credential.get("transports")
    if transports is not None:
        decoded["transports"] = transports

    raw_id_bytes = _decode_binary_field(credential.get("rawId"))
    if raw_id_bytes:
        raw_id, raw_id_encoding = raw_id_bytes
        decoded["rawId"] = {
            "raw": credential.get("rawId"),
            "binary": details_runtime._binary_summary(raw_id, raw_id_encoding),
        }
    elif "rawId" in credential:
        decoded["rawId"] = {"raw": credential.get("rawId")}

    client_ext = credential.get("clientExtensionResults")
    if client_ext is None and "getClientExtensionResults" in credential:
        client_ext = credential.get("getClientExtensionResults")
    if client_ext is not None:
        decoded["clientExtensionResults"] = make_json_safe(client_ext)

    if raw_text is not None:
        decoded["rawJson"] = raw_text

    attestation_entry = _decode_binary_field(response_mapping.get("attestationObject"))
    authenticator_entry = _decode_binary_field(response_mapping.get("authenticatorData"))

    format_label = "PublicKeyCredential"
    if attestation_entry:
        format_label = "PublicKeyCredential (registration)"
        att_bytes, att_encoding = attestation_entry
        response_details["attestationObject"] = {
            "raw": response_mapping.get("attestationObject"),
            "binary": details_runtime._binary_summary(att_bytes, att_encoding),
            "details": details_runtime._parse_attestation_object(att_bytes),
        }

    if authenticator_entry:
        if format_label == "PublicKeyCredential":
            format_label = "PublicKeyCredential (authentication)"
        auth_bytes, auth_encoding = authenticator_entry
        response_details["authenticatorData"] = {
            "raw": response_mapping.get("authenticatorData"),
            "binary": details_runtime._binary_summary(auth_bytes, auth_encoding),
            "details": details_runtime._describe_authenticator_data_bytes(auth_bytes),
        }

    client_data_entry = _decode_binary_field(response_mapping.get("clientDataJSON"))
    if client_data_entry:
        client_bytes, client_encoding = client_data_entry
        response_details["clientDataJSON"] = {
            "raw": response_mapping.get("clientDataJSON"),
            "binary": details_runtime._binary_summary(client_bytes, client_encoding),
            "details": details_runtime._describe_client_data_from_bytes(client_bytes),
        }

    signature_entry = _decode_binary_field(response_mapping.get("signature"))
    if signature_entry:
        sig_bytes, sig_encoding = signature_entry
        response_details["signature"] = {
            "raw": response_mapping.get("signature"),
            "binary": details_runtime._binary_summary(sig_bytes, sig_encoding),
        }

    user_handle_entry = _decode_binary_field(response_mapping.get("userHandle"))
    if user_handle_entry:
        handle_bytes, handle_encoding = user_handle_entry
        response_details["userHandle"] = {
            "raw": response_mapping.get("userHandle"),
            "binary": details_runtime._binary_summary(handle_bytes, handle_encoding),
        }

    decoded["response"] = response_details

    return {
        "format": format_label,
        "inputEncoding": "json",
        "decoded": decoded,
    }


def _decode_pem_certificates(text: str) -> dict[str, Any]:
    certificates = []
    for match in _PEM_CERT_PATTERN.finditer(text):
        cert_bytes = try_decode_base64(match.group("body"))
        if cert_bytes is None:
            continue
        certificates.append(cert_bytes)

    if not certificates:
        raise ValueError("No PEM certificate data found.")

    decoded_details = [
        serialize_attestation_certificate(cert_bytes) for cert_bytes in certificates
    ]

    payload: dict[str, Any]
    if len(decoded_details) == 1:
        payload = decoded_details[0]
    else:
        payload = {"certificates": decoded_details}

    payload.setdefault("rawPem", text.strip())

    return {
        "format": "X.509 certificate (PEM)",
        "inputEncoding": "pem",
        "decoded": payload,
    }


def _decode_binary_payload(data: bytes, encoding: str) -> dict[str, Any]:
    text_version = details_runtime._try_decode_utf8(data)

    if text_version and _looks_like_pem(text_version):
        result = _decode_pem_certificates(text_version)
        result["inputEncoding"] = encoding
        result["binary"] = details_runtime._binary_summary(data, encoding)
        return result

    if text_version:
        json_obj = _try_parse_json(text_version)
        if json_obj is not None:
            if isinstance(json_obj, Mapping) and details_runtime._is_client_data_dict(json_obj):
                details = details_runtime._describe_client_data_from_bytes(data)
                return {
                    "format": "WebAuthn client data (binary)",
                    "inputEncoding": encoding,
                    "decoded": details,
                    "binary": details_runtime._binary_summary(data, encoding),
                }
            return {
                "format": "JSON (binary)",
                "inputEncoding": encoding,
                "decoded": json_obj,
                "binary": details_runtime._binary_summary(data, encoding),
            }

    certificate_result = _try_decode_certificate_bytes(data, encoding)
    if certificate_result is not None:
        return certificate_result

    attestation_result = _try_decode_attestation_object(data, encoding)
    if attestation_result is not None:
        return attestation_result

    authenticator_result = _try_decode_authenticator_data(data, encoding)
    if authenticator_result is not None:
        return authenticator_result

    cbor_result = cbor_runtime._try_decode_cbor(data, encoding)
    if cbor_result is not None:
        return cbor_result

    return {
        "format": "Binary data",
        "inputEncoding": encoding,
        "decoded": details_runtime._binary_summary(data, encoding),
    }


def _sniff_binary_input(value: str) -> SniffResult:
    """Decode decoder input and report which encoding actually matched.

    The label comes from the decoder that succeeded, not from scanning the
    input for ``-``/``_``: a base64url payload that happens to use none of
    those characters is byte-identical to the same text read as standard
    base64, and :attr:`~server.app.encoding.SniffResult.ambiguous` says so
    instead of the pipeline picking one and asserting it.
    """

    if not "".join(value.split()):
        raise ValueError("No binary data present.")

    try:
        return sniff(value)
    except EncodingError as exc:
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


def _decode_binary_input(value: str) -> tuple[bytes, str]:
    result = _sniff_binary_input(value)
    return result.data, result.encoding


def _decode_binary_field(value: Any) -> tuple[bytes, str] | None:
    if isinstance(value, str):
        try:
            return _decode_binary_input(value)
        except ValueError:
            return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), "binary"
    return None


def _try_parse_json(value: str) -> Any | None:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _looks_like_pem(value: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in value.upper()


def _try_decode_certificate_bytes(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        x509.load_der_x509_certificate(data)
    except Exception:
        return None

    return {
        "format": "X.509 certificate (DER)",
        "inputEncoding": encoding,
        "decoded": serialize_attestation_certificate(data),
        "binary": details_runtime._binary_summary(data, encoding),
    }


def _try_decode_attestation_object(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details = details_runtime._parse_attestation_object(data)
    except Exception:
        return None

    return {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": details_runtime._binary_summary(data, encoding),
    }


def _try_decode_authenticator_data(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details = details_runtime._describe_authenticator_data_bytes(data)
    except Exception:
        return None

    return {
        "format": "Authenticator data (binary)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": details_runtime._binary_summary(data, encoding),
    }


def _expand_cbor_value(value: Any) -> Any:
    if isinstance(value, ByteBuffer):
        return details_runtime._binary_summary(value.getvalue())
    if isinstance(value, (bytes, bytearray, memoryview)):
        return details_runtime._binary_summary(bytes(value))
    if isinstance(value, Mapping):
        expanded: dict[str, Any] = {}
        for key, entry in value.items():
            expanded[str(key)] = _expand_cbor_value(entry)
        return expanded
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_expand_cbor_value(item) for item in value]
    return make_json_safe(value)


def decode_payload_text(value: str) -> dict[str, Any]:
    """Decode ``value`` into a structured representation."""

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    parsed_json = _try_parse_json(trimmed)
    if parsed_json is not None:
        result = _decode_json_object(parsed_json, raw_text=trimmed)
    elif _looks_like_pem(trimmed):
        result = _decode_pem_certificates(trimmed)
    else:
        data, encoding = _decode_binary_input(trimmed)
        result = _decode_binary_payload(data, encoding)

    return result_runtime._prepare_decoder_response(result)
