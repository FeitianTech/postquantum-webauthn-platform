"""Utilities for decoding WebAuthn-related payloads for the demo decoder."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import string
import struct
import uuid
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import cbor2
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fido2 import cbor
from fido2.utils import ByteBuffer
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData

from .attestation import (
    colon_hex,
    encode_base64url,
    format_hex_bytes_lines,
    format_hex_string_lines,
    make_json_safe,
    serialize_attestation_certificate,
    summarize_authenticator_extensions,
)

__all__ = ["decode_payload_text"]

_CTAP_COMMAND_MAP: Dict[int, str] = {
    0x01: "AuthenticatorMakeCredential command",
    0x02: "AuthenticatorGetAssertion command",
}

_CTAP_STATUS_MAP: Dict[int, str] = {
    0x00: "Success status",
}



def _extract_ctap_prefix(data: bytes) -> Tuple[Optional[Dict[str, Any]], bytes]:
    if not data:
        return None, data
    code = data[0]
    if code in _CTAP_COMMAND_MAP:
        return (
            {
                "code": code,
                "codeHex": f"0x{code:02x}",
                "meaning": _CTAP_COMMAND_MAP[code],
                "kind": "command",
            },
            data[1:],
        )
    if code in _CTAP_STATUS_MAP:
        return (
            {
                "code": code,
                "codeHex": f"0x{code:02x}",
                "meaning": _CTAP_STATUS_MAP[code],
                "kind": "status",
            },
            data[1:],
        )
    return None, data


def _is_padding_bytes(data: bytes) -> bool:
    if not data:
        return True
    return all(byte in (0x00, 0xFF) for byte in data)


def _coerce_cbor_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def _stringify_mapping_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _stringify_mapping_keys(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_stringify_mapping_keys(item) for item in value]
    return value
def _make_hex_only(value: Any) -> Any:
    if isinstance(value, ByteBuffer):
        return value.getvalue().hex()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {str(key): _make_hex_only(val) for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_make_hex_only(item) for item in value]
    return value


def _hex_json_safe(value: Any) -> Any:
    return _make_hex_only(value)


def _json_safe_with_stringified_keys(value: Any) -> Any:
    return _stringify_mapping_keys(make_json_safe(value))

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def decode_payload_text(value: str) -> Dict[str, Any]:
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

    return _prepare_decoder_response(result)


def _decode_json_object(value: Any, raw_text: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(value, Mapping) and _is_public_key_credential(value):
        return _decode_public_key_credential(value, raw_text=raw_text)

    if isinstance(value, Mapping) and _is_client_data_dict(value):
        details = _build_client_data_details(value, raw_text=raw_text)
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
    credential: Mapping[str, Any], raw_text: Optional[str] = None
) -> Dict[str, Any]:
    response = credential.get("response")
    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}

    response_details: Dict[str, Any] = {
        key: value
        for key, value in response_mapping.items()
        if key
        not in {"attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle"}
    }

    decoded: Dict[str, Any] = {
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
            "binary": _binary_summary(raw_id, raw_id_encoding),
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
            "binary": _binary_summary(att_bytes, att_encoding),
            "details": _parse_attestation_object(att_bytes),
        }

    if authenticator_entry:
        if format_label == "PublicKeyCredential":
            format_label = "PublicKeyCredential (authentication)"
        auth_bytes, auth_encoding = authenticator_entry
        response_details["authenticatorData"] = {
            "raw": response_mapping.get("authenticatorData"),
            "binary": _binary_summary(auth_bytes, auth_encoding),
            "details": _describe_authenticator_data_bytes(auth_bytes),
        }

    client_data_entry = _decode_binary_field(response_mapping.get("clientDataJSON"))
    if client_data_entry:
        client_bytes, client_encoding = client_data_entry
        response_details["clientDataJSON"] = {
            "raw": response_mapping.get("clientDataJSON"),
            "binary": _binary_summary(client_bytes, client_encoding),
            "details": _describe_client_data_from_bytes(client_bytes),
        }

    signature_entry = _decode_binary_field(response_mapping.get("signature"))
    if signature_entry:
        sig_bytes, sig_encoding = signature_entry
        response_details["signature"] = {
            "raw": response_mapping.get("signature"),
            "binary": _binary_summary(sig_bytes, sig_encoding),
        }

    user_handle_entry = _decode_binary_field(response_mapping.get("userHandle"))
    if user_handle_entry:
        handle_bytes, handle_encoding = user_handle_entry
        response_details["userHandle"] = {
            "raw": response_mapping.get("userHandle"),
            "binary": _binary_summary(handle_bytes, handle_encoding),
        }

    decoded["response"] = response_details

    return {
        "format": format_label,
        "inputEncoding": "json",
        "decoded": decoded,
    }


def _decode_pem_certificates(text: str) -> Dict[str, Any]:
    certificates = []
    for match in _PEM_CERT_PATTERN.finditer(text):
        body = re.sub(r"[^A-Za-z0-9+/=]", "", match.group("body"))
        if not body:
            continue
        try:
            cert_bytes = base64.b64decode(body)
        except (ValueError, binascii.Error):
            continue
        certificates.append(cert_bytes)

    if not certificates:
        raise ValueError("No PEM certificate data found.")

    decoded_details = [
        serialize_attestation_certificate(cert_bytes) for cert_bytes in certificates
    ]

    payload: Dict[str, Any]
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


def _decode_binary_payload(data: bytes, encoding: str) -> Dict[str, Any]:
    text_version = _try_decode_utf8(data)

    if text_version and _looks_like_pem(text_version):
        result = _decode_pem_certificates(text_version)
        result["inputEncoding"] = encoding
        result["binary"] = _binary_summary(data, encoding)
        return result

    if text_version:
        json_obj = _try_parse_json(text_version)
        if json_obj is not None:
            if isinstance(json_obj, Mapping) and _is_client_data_dict(json_obj):
                details = _describe_client_data_from_bytes(data)
                return {
                    "format": "WebAuthn client data (binary)",
                    "inputEncoding": encoding,
                    "decoded": details,
                    "binary": _binary_summary(data, encoding),
                }
            return {
                "format": "JSON (binary)",
                "inputEncoding": encoding,
                "decoded": json_obj,
                "binary": _binary_summary(data, encoding),
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

    cbor_result = _try_decode_cbor(data, encoding)
    if cbor_result is not None:
        return cbor_result

    return {
        "format": "Binary data",
        "inputEncoding": encoding,
        "decoded": _binary_summary(data, encoding),
    }


def _decode_binary_input(value: str) -> Tuple[bytes, str]:
    cleaned = "".join(value.split())
    if not cleaned:
        raise ValueError("No binary data present.")

    hex_candidate = re.sub(r"0x", "", cleaned, flags=re.IGNORECASE).replace(":", "")
    if hex_candidate and all(char in string.hexdigits for char in hex_candidate):
        if len(hex_candidate) % 2:
            hex_candidate = "0" + hex_candidate
        return bytes.fromhex(hex_candidate), "hex"

    has_url_chars = any(char in "-_" for char in cleaned)
    base64_candidate = cleaned.replace("-", "+").replace("_", "/")
    padding = (-len(base64_candidate)) % 4
    if padding:
        base64_candidate += "=" * padding
    try:
        decoded = base64.b64decode(base64_candidate, validate=True)
        return decoded, "base64url" if has_url_chars else "base64"
    except (ValueError, binascii.Error):
        pass

    padding = (-len(cleaned)) % 4
    try:
        decoded = base64.urlsafe_b64decode(cleaned + "=" * padding)
        return decoded, "base64url"
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


def _decode_binary_field(value: Any) -> Optional[Tuple[bytes, str]]:
    if isinstance(value, str):
        try:
            return _decode_binary_input(value)
        except ValueError:
            return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), "binary"
    return None


def _try_parse_json(value: str) -> Optional[Any]:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _looks_like_pem(value: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in value.upper()


def _try_decode_certificate_bytes(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    try:
        x509.load_der_x509_certificate(data)
    except Exception:
        return None

    return {
        "format": "X.509 certificate (DER)",
        "inputEncoding": encoding,
        "decoded": serialize_attestation_certificate(data),
        "binary": _binary_summary(data, encoding),
    }


def _try_decode_attestation_object(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    try:
        details = _parse_attestation_object(data)
    except Exception:
        return None

    return {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
    }


def _try_decode_authenticator_data(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    try:
        details = _describe_authenticator_data_bytes(data)
    except Exception:
        return None

    return {
        "format": "Authenticator data (binary)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
    }


class _CborDecodingError(ValueError):
    """Internal error raised when a CBOR payload cannot be parsed."""

    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.offset = offset


def _ensure_cbor_available(data: bytes, offset: int, length: int) -> None:
    if length < 0 or offset + length > len(data):
        raise _CborDecodingError("Unexpected end of CBOR data.", offset)


def _read_cbor_length(
    info: int, data: bytes, offset: int, *, allow_indefinite: bool = False
) -> Tuple[Optional[int], int]:
    if info < 24:
        return info, offset
    if info == 24:
        _ensure_cbor_available(data, offset, 1)
        return data[offset], offset + 1
    if info == 25:
        _ensure_cbor_available(data, offset, 2)
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if info == 26:
        _ensure_cbor_available(data, offset, 4)
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if info == 27:
        _ensure_cbor_available(data, offset, 8)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info == 30:
        _ensure_cbor_available(data, offset, 8)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info == 31 and allow_indefinite:
        return None, offset
    raise _CborDecodingError("Unsupported CBOR additional information.", offset)


def _float_summary(value: float) -> str:
    if math.isnan(value):
        return "float(NaN)"
    if math.isinf(value):
        return "float(+Infinity)" if value > 0 else "float(-Infinity)"
    return f"float({value})"


def _parse_cbor_item(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    if offset >= len(data):
        raise _CborDecodingError("Unexpected end of CBOR data.", offset)

    initial = data[offset]
    offset += 1
    major_type = initial >> 5
    info = initial & 0x1F

    if major_type == 0:
        if info == 30:
            node = {
                "majorType": 0,
                "type": "unsigned",
                "value": 30,
                "summary": "30",
            }
            return node, offset
        value, offset = _read_cbor_length(info, data, offset)
        if value is None:
            raise _CborDecodingError("Invalid indefinite length for unsigned integer.", offset)
        node = {"majorType": 0, "type": "unsigned", "value": value, "summary": str(value)}
        return node, offset

    if major_type == 1:
        if info == 30:
            actual = -31
            node = {"majorType": 1, "type": "negative", "value": actual, "summary": str(actual)}
            return node, offset
        value, offset = _read_cbor_length(info, data, offset)
        if value is None:
            raise _CborDecodingError("Invalid indefinite length for negative integer.", offset)
        actual = -1 - value
        node = {"majorType": 1, "type": "negative", "value": actual, "summary": str(actual)}
        return node, offset

    if major_type == 2:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        if length is None:
            segments: List[Dict[str, Any]] = []
            raw_segments: List[bytes] = []
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    segment, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                if segment.get("majorType") != 2:
                    raise _CborDecodingError(
                        "Indefinite byte string segment is not a byte string.", offset
                    )
                segments.append(segment)
                segment_hex = segment.get("hex")
                segment_data = bytes.fromhex(segment_hex) if isinstance(segment_hex, str) else b""
                raw_segments.append(segment_data)
            raw = b"".join(raw_segments)
            node = {
                "majorType": 2,
                "type": "byte string",
                "length": len(raw),
                "hex": raw.hex(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "base64url": encode_base64url(raw),
                "indefinite": True,
                "chunks": segments,
            }
            node["summary"] = f"bytes[{node['length']}]"
            return node, offset
        try:
            _ensure_cbor_available(data, offset, length)
        except _CborDecodingError:
            available = max(len(data) - offset, 0)
            raw = data[offset : offset + available]
            offset += available
            node = {
                "majorType": 2,
                "type": "byte string",
                "length": length,
                "hex": raw.hex(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "base64url": encode_base64url(raw),
                "truncated": True,
            }
            node["summary"] = f"bytes[{available}] (truncated from {length})"
            return node, offset
        raw = data[offset : offset + length]
        offset += length
        node = {
            "majorType": 2,
            "type": "byte string",
            "length": length,
            "hex": raw.hex(),
            "base64": base64.b64encode(raw).decode("ascii"),
            "base64url": encode_base64url(raw),
        }
        node["summary"] = f"bytes[{length}]"
        return node, offset

    if major_type == 3:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        if length is None:
            segments: List[Dict[str, Any]] = []
            text_parts: List[str] = []
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    segment, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                if segment.get("majorType") != 3:
                    raise _CborDecodingError(
                        "Indefinite text string segment is not a text string.", offset
                    )
                segments.append(segment)
                text_parts.append(str(segment.get("value", "")))
            value = "".join(text_parts)
            byte_length = len(value.encode("utf-8"))
            node = {
                "majorType": 3,
                "type": "text string",
                "length": byte_length,
                "value": value,
                "indefinite": True,
                "segments": segments,
            }
            summary = value if len(value) <= 32 else f"{value[:29]}..."
            node["summary"] = f'"{summary}"'
            return node, offset
        _ensure_cbor_available(data, offset, length)
        raw = data[offset : offset + length]
        offset += length
        try:
            value = raw.decode("utf-8")
            summary = value if len(value) <= 32 else f"{value[:29]}..."
            node = {
                "majorType": 3,
                "type": "text string",
                "length": length,
                "value": value,
                "summary": f'"{summary}"',
            }
        except UnicodeDecodeError:
            node = {
                "majorType": 3,
                "type": "text string",
                "length": length,
                "hex": raw.hex(),
                "error": "Invalid UTF-8 in text string.",
                "summary": f"text[{length}]",
            }
        return node, offset

    if major_type == 4:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        items: List[Dict[str, Any]] = []
        if length is None:
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    item, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                items.append(item)
            length = len(items)
            node = {
                "majorType": 4,
                "type": "array",
                "length": length,
                "items": items,
                "indefinite": True,
            }
        else:
            for _ in range(length):
                if offset >= len(data):
                    break
                try:
                    item, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                items.append(item)
            node = {"majorType": 4, "type": "array", "length": length, "items": items}
        node["summary"] = f"array[{node['length']}]"
        return node, offset

    if major_type == 5:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        entries: List[Dict[str, Any]] = []
        if length is None:
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    key, offset = _parse_cbor_item(data, offset)
                    if offset >= len(data):
                        break
                    if data[offset] == 0xFF:
                        break
                    value, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                entry = {
                    "keySummary": key.get("summary"),
                    "key": key,
                    "value": value,
                }
                summary = value.get("summary")
                if summary is not None:
                    entry["valueSummary"] = summary
                entries.append(entry)
            length = len(entries)
            node = {
                "majorType": 5,
                "type": "map",
                "length": length,
                "entries": entries,
                "indefinite": True,
            }
        else:
            for _ in range(length):
                if offset >= len(data):
                    break
                try:
                    key, offset = _parse_cbor_item(data, offset)
                    value, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                entry = {
                    "keySummary": key.get("summary"),
                    "key": key,
                    "value": value,
                }
                summary = value.get("summary")
                if summary is not None:
                    entry["valueSummary"] = summary
                entries.append(entry)
            node = {"majorType": 5, "type": "map", "length": length, "entries": entries}
        node["summary"] = f"map[{node['length']}]"
        return node, offset

    if major_type == 6:
        tag_value, offset = _read_cbor_length(info, data, offset)
        if tag_value is None:
            raise _CborDecodingError("Invalid indefinite length for CBOR tag.", offset)
        tagged_item, offset = _parse_cbor_item(data, offset)
        node = {
            "majorType": 6,
            "type": "tag",
            "tag": tag_value,
            "value": tagged_item,
            "summary": f"tag({tag_value})",
        }
        return node, offset

    if major_type == 7:
        if info == 20:
            return {"majorType": 7, "type": "boolean", "value": False, "summary": "false"}, offset
        if info == 21:
            return {"majorType": 7, "type": "boolean", "value": True, "summary": "true"}, offset
        if info == 22:
            return {"majorType": 7, "type": "null", "summary": "null"}, offset
        if info == 23:
            return {"majorType": 7, "type": "undefined", "summary": "undefined"}, offset
        if info == 24:
            _ensure_cbor_available(data, offset, 1)
            simple_value = data[offset]
            offset += 1
            summary = f"simple({simple_value})"
            return {
                "majorType": 7,
                "type": "simple",
                "value": simple_value,
                "summary": summary,
            }, offset
        if info == 25:
            _ensure_cbor_available(data, offset, 2)
            raw = data[offset : offset + 2]
            offset += 2
            value = struct.unpack(">e", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "half",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 26:
            _ensure_cbor_available(data, offset, 4)
            raw = data[offset : offset + 4]
            offset += 4
            value = struct.unpack(">f", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "single",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 27:
            _ensure_cbor_available(data, offset, 8)
            raw = data[offset : offset + 8]
            offset += 8
            value = struct.unpack(">d", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "double",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 31:
            raise _CborDecodingError("Unexpected break code outside indefinite container.", offset)
        summary = f"simple({info})"
        return {"majorType": 7, "type": "simple", "value": info, "summary": summary}, offset

    raise _CborDecodingError("Unsupported CBOR major type.", offset)


def _decode_cbor_structure(data: bytes) -> Tuple[Dict[str, Any], int]:
    node, offset = _parse_cbor_item(data, 0)
    node.setdefault("byteLength", offset)
    return node, offset


def _structure_to_value(node: Mapping[str, Any]) -> Any:
    major_type = node.get("majorType")
    node_type = node.get("type")

    if major_type in (0, 1, 7):
        if node_type == "null":
            return None
        if node_type == "undefined":
            return None
        if node_type == "boolean":
            return bool(node.get("value"))
        return node.get("value")

    if major_type == 2:
        hex_value = node.get("hex")
        if isinstance(hex_value, str):
            try:
                return bytes.fromhex(hex_value)
            except ValueError:
                return b""
        chunks = node.get("chunks")
        if isinstance(chunks, Sequence):
            return b"".join(
                bytes(_structure_to_value(chunk) or b"")  # type: ignore[arg-type]
                for chunk in chunks
            )
        return b""

    if major_type == 3:
        text_value = node.get("value")
        if isinstance(text_value, str):
            return text_value
        return ""

    if major_type == 4:
        items = node.get("items")
        if not isinstance(items, Sequence):
            return []
        return [_structure_to_value(item) for item in items]

    if major_type == 5:
        entries = node.get("entries")
        if not isinstance(entries, Sequence):
            return {}
        result: Dict[Any, Any] = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            key_node = entry.get("key")
            value_node = entry.get("value")
            key = _structure_to_value(key_node) if isinstance(key_node, Mapping) else None
            value = (
                _structure_to_value(value_node)
                if isinstance(value_node, Mapping)
                else value_node
            )
            if key is None:
                continue
            try:
                result[key] = value
            except TypeError:
                result[str(key)] = value
        return result

    if major_type == 6:
        tagged_value = node.get("value")
        converted = (
            _structure_to_value(tagged_value)
            if isinstance(tagged_value, Mapping)
            else tagged_value
        )
        return {"tag": node.get("tag"), "value": converted}

    return node.get("value")


def _expand_cbor_value(value: Any) -> Any:
    if isinstance(value, ByteBuffer):
        return _binary_summary(value.getvalue())
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _binary_summary(bytes(value))
    if isinstance(value, Mapping):
        expanded: Dict[str, Any] = {}
        for key, entry in value.items():
            expanded[str(key)] = _expand_cbor_value(entry)
        return expanded
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_expand_cbor_value(item) for item in value]
    return make_json_safe(value)


def _lenient_read_uint(info: int, data: bytes, offset: int) -> Tuple[int, int]:
    if info <= 23:
        return info, offset
    if info == 24:
        if offset >= len(data):
            return 0, offset
        return data[offset], offset + 1
    if info == 25:
        if offset + 2 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if info == 26:
        if offset + 4 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if info == 27:
        if offset + 8 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info in {28, 29, 30}:
        return info, offset
    return 0, offset


def _lenient_decode_from(data: bytes, offset: int = 0) -> Tuple[Any, int]:
    if offset >= len(data):
        return None, len(data)

    initial = data[offset]
    offset += 1
    major_type = initial >> 5
    info = initial & 0x1F

    if major_type == 0:
        value, offset = _lenient_read_uint(info, data, offset)
        return value, offset

    if major_type == 1:
        value, offset = _lenient_read_uint(info, data, offset)
        return -1 - value, offset

    if major_type == 2:
        if info == 31:
            chunks: List[bytes] = []
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                chunk, offset = _lenient_decode_from(data, offset)
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    break
            return b"".join(chunks), offset
        length, offset = _lenient_read_uint(info, data, offset)
        length = min(length, len(data) - offset)
        raw = data[offset : offset + length]
        offset += length
        return raw, offset

    if major_type == 3:
        if info == 31:
            parts: List[str] = []
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                segment, offset = _lenient_decode_from(data, offset)
                if isinstance(segment, str):
                    parts.append(segment)
            return "".join(parts), offset
        length, offset = _lenient_read_uint(info, data, offset)
        length = min(length, len(data) - offset)
        raw = data[offset : offset + length]
        offset += length
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.decode("utf-8", errors="replace")
        return value, offset

    if major_type == 4:
        items: List[Any] = []
        if info == 31:
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                item, offset = _lenient_decode_from(data, offset)
                if item is None and offset >= len(data):
                    break
                items.append(item)
            return items, offset
        length, offset = _lenient_read_uint(info, data, offset)
        for _ in range(length):
            if offset >= len(data):
                break
            item, offset = _lenient_decode_from(data, offset)
            if item is None and offset >= len(data):
                break
            items.append(item)
        return items, offset

    if major_type == 5:
        mapping: Dict[Any, Any] = {}
        if info == 31:
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                key, offset = _lenient_decode_from(data, offset)
                value, offset = _lenient_decode_from(data, offset)
                if key is None or value is None:
                    break
                try:
                    mapping[key] = value
                except TypeError:
                    mapping[str(key)] = value
            return mapping, offset
        length, offset = _lenient_read_uint(info, data, offset)
        for _ in range(length):
            if offset >= len(data):
                break
            key, offset = _lenient_decode_from(data, offset)
            if key is None and offset >= len(data):
                break
            value, offset = _lenient_decode_from(data, offset)
            if value is None and offset >= len(data):
                break
            try:
                mapping[key] = value
            except TypeError:
                mapping[str(key)] = value
        return mapping, offset

    if major_type == 6:
        tag_value, offset = _lenient_read_uint(info, data, offset)
        tagged_item, offset = _lenient_decode_from(data, offset)
        return {"tag": tag_value, "value": tagged_item}, offset

    if major_type == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        if info == 23:
            return None, offset
        if info == 24:
            if offset < len(data):
                value = data[offset]
            else:
                value = 0
            return value, offset + 1
        if info == 25:
            if offset + 2 <= len(data):
                raw = data[offset : offset + 2]
                offset += 2
                return struct.unpack(">e", raw)[0], offset
            return 0.0, len(data)
        if info == 26:
            if offset + 4 <= len(data):
                raw = data[offset : offset + 4]
                offset += 4
                return struct.unpack(">f", raw)[0], offset
            return 0.0, len(data)
        if info == 27:
            if offset + 8 <= len(data):
                raw = data[offset : offset + 8]
                offset += 8
                return struct.unpack(">d", raw)[0], offset
            return 0.0, len(data)
        return info, offset

    return None, offset


def _decode_cbor_sequence(payload: bytes) -> Tuple[List[Dict[str, Any]], List[Any], int, bytes]:
    structures: List[Dict[str, Any]] = []
    values: List[Any] = []
    consumed_total = 0
    remaining = payload

    while remaining:
        consumed_value: Optional[int] = None
        predecoded_structure: Optional[Dict[str, Any]] = None
        try:
            value, rest_after_value = cbor.decode_from(remaining)
            consumed_value = len(remaining) - len(rest_after_value)
        except Exception:
            try:
                fp = BytesIO(remaining)
                decoder = cbor2.CBORDecoder(fp)
                value = decoder.decode()
            except Exception:
                try:
                    structure, consumed_fallback = _decode_cbor_structure(remaining)
                except _CborDecodingError:
                    try:
                        value, consumed_fallback = _lenient_decode_from(remaining)
                    except Exception:
                        break
                    else:
                        consumed_value = consumed_fallback
                        rest_after_value = remaining[consumed_fallback:]
                        structure = {
                            "summary": "Decoded value (lenient)",
                            "type": type(value).__name__,
                            "value": _json_safe_with_stringified_keys(value),
                            "byteLength": consumed_fallback,
                            "lenient": True,
                        }
                        predecoded_structure = structure
                else:
                    value = _structure_to_value(structure)
                    consumed_value = consumed_fallback
                    rest_after_value = remaining[consumed_fallback:]
                    predecoded_structure = structure
            else:
                consumed_value = fp.tell()
                rest_after_value = remaining[consumed_value:]

        if consumed_value is None or consumed_value <= 0:
            break

        try:
            if predecoded_structure is not None:
                structure = predecoded_structure
                consumed_struct = predecoded_structure.get("byteLength", consumed_value)
            else:
                structure, consumed_struct = _decode_cbor_structure(remaining)
            consumed = consumed_struct
        except _CborDecodingError:
            structure = {
                "summary": "Decoded value",
                "type": type(value).__name__,
                "value": _json_safe_with_stringified_keys(value),
                "byteLength": consumed_value,
            }
            consumed = consumed_value
        else:
            if consumed <= 0:
                consumed = consumed_value

        if consumed <= 0:
            break

        structures.append(structure)
        values.append(value)
        consumed_total += consumed
        remaining = remaining[consumed:]

    return structures, values, consumed_total, remaining


def _merge_ctap_make_credential(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    extra_structures: List[Dict[str, Any]],
    extra_values: List[Any],
) -> Tuple[Dict[str, Any], Mapping[Any, Any], List[Dict[str, Any]], List[Any], Optional[bytes]]:
    signature_bytes: Optional[bytes] = None

    if isinstance(value, Mapping) and value.get("al&") == "sig":
        normalized_value = dict(value)
        normalized_value.pop("al&", None)

        def _extract_alg(mapping: Mapping[Any, Any]) -> Optional[int]:
            for key in ("alg", "algorithm", 1, "1", 3, "3"):
                raw = mapping.get(key)
                if isinstance(raw, int):
                    return raw
            return None

        def _extract_sig(mapping: Mapping[Any, Any]) -> Optional[bytes]:
            for key in ("sig", "signature", 2, "2", 3, "3"):
                if key in mapping:
                    coerced = _coerce_cbor_bytes(mapping[key])
                    if coerced is not None:
                        return coerced
            return None

        alg_value = _extract_alg(normalized_value)
        truncated_sig = _coerce_cbor_bytes(normalized_value.pop("sig", None))
        if truncated_sig is None:
            truncated_sig = _coerce_cbor_bytes(normalized_value.pop("signature", None))
        normalized_value.pop("alg", None)
        normalized_value.pop("algorithm", None)
        normalized_value.pop("attStmt", None)
        normalized_value.pop("attstmt", None)

        att_structure_override: Optional[Dict[str, Any]] = None
        att_stmt_base: Optional[Mapping[Any, Any]] = None

        if extra_values:
            candidate = extra_values[0]
            if isinstance(candidate, Mapping):
                candidate_alg = _extract_alg(candidate)
                candidate_sig = _extract_sig(candidate)
                if candidate_alg is not None or candidate_sig is not None:
                    alg_value = candidate_alg if candidate_alg is not None else alg_value
                    if candidate_sig is not None:
                        signature_bytes = candidate_sig
                    att_stmt_base = candidate
                    extra_values = extra_values[1:]
                    if extra_structures:
                        att_structure_override = extra_structures[0]
                        extra_structures = extra_structures[1:]
            elif isinstance(candidate, (bytes, bytearray, memoryview, ByteBuffer)):
                signature_bytes = _coerce_cbor_bytes(candidate)
                extra_values = extra_values[1:]
                if extra_structures:
                    extra_structures = extra_structures[1:]

        if signature_bytes is None:
            signature_bytes = truncated_sig

        if signature_bytes is not None:
            if alg_value is None:
                alg_value = -7

            if att_stmt_base is not None:
                att_stmt = dict(att_stmt_base)
                att_stmt.pop("sig", None)
                att_stmt.pop("signature", None)
                att_stmt.pop("alg", None)
                att_stmt.pop("algorithm", None)
                att_stmt["alg"] = alg_value
                att_stmt["sig"] = signature_bytes
            else:
                att_stmt = {"alg": alg_value, "sig": signature_bytes}
            normalized_value[3] = att_stmt

            if isinstance(att_structure_override, Mapping):
                att_structure = att_structure_override
            else:
                att_structure, _ = _decode_cbor_structure(cbor.encode(att_stmt))

            entries = structure.get("entries")
            if isinstance(entries, list) and entries:
                entries[-1] = {
                    "keySummary": "3",
                    "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                    "value": att_structure,
                    "valueSummary": att_structure.get("summary") if isinstance(att_structure, Mapping) else None,
                }
            structure["length"] = len(entries) if isinstance(entries, list) else structure.get("length", 3)
            value = normalized_value
            return structure, value, extra_structures, extra_values, signature_bytes

    return structure, value, extra_structures, extra_values, None


def _repair_make_credential_entries(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    *,
    default_alg: int = -50,
) -> Tuple[Dict[str, Any], Mapping[Any, Any], Optional[bytes]]:
    if not isinstance(value, dict):
        return structure, value, None

    signature_key = None
    signature_node: Optional[Dict[str, Any]] = None
    entries = structure.get("entries")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            key_info = entry.get("key") if isinstance(entry, Mapping) else None
            if not isinstance(key_info, Mapping):
                continue
            major_type = key_info.get("majorType")
            if major_type in {2, 7} or (major_type == 0 and key_info.get("value") == 13):
                signature_key = key_info
                signature_node = entry
                entries.pop(idx)
                break

    signature_bytes: Optional[bytes] = None
    if signature_key is not None:
        hex_value = signature_key.get("hex")
        if isinstance(hex_value, str):
            try:
                signature_bytes = bytes.fromhex(hex_value)
            except ValueError:
                signature_bytes = None

    polished_value = dict(value)
    pop_keys: List[Any] = []
    for key in list(polished_value.keys()):
        if isinstance(key, (bytes, bytearray)):
            pop_keys.append(key)
    for key in pop_keys:
        polished_value.pop(key, None)

    if 13 in polished_value and 3 not in polished_value:
        raw_entry = polished_value.pop(13)
        if isinstance(raw_entry, list):
            segments: List[bytes] = []
            alg_candidate: Optional[int] = None
            for item in raw_entry:
                if isinstance(item, (bytes, bytearray)):
                    segments.append(bytes(item))
                elif isinstance(item, Mapping) and alg_candidate is None:
                    for possible in item.values():
                        if isinstance(possible, int):
                            alg_candidate = possible
                            break
            if segments:
                signature_bytes = b"".join(segments)
                if alg_candidate is not None:
                    default_alg = alg_candidate

    if signature_bytes is not None:
        polished_value[3] = {"sig": signature_bytes, "alg": default_alg}
        att_stmt_structure, _ = _decode_cbor_structure(
            cbor.encode({"sig": signature_bytes, "alg": default_alg})
        )
        if isinstance(entries, list):
            entries.append(
                {
                    "keySummary": "3",
                    "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                    "value": att_stmt_structure,
                    "valueSummary": att_stmt_structure.get("summary"),
                }
            )
            structure["length"] = len(entries)
            structure["summary"] = f"map[{len(entries)}]"

    return structure, polished_value, signature_bytes


def _repair_get_assertion_entries(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
) -> Tuple[Dict[str, Any], Mapping[Any, Any], Optional[bytes]]:
    if not isinstance(value, dict):
        return structure, value, None

    signature_entry = None
    entries = structure.get("entries")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            key_info = entry.get("key") if isinstance(entry, Mapping) else None
            if not isinstance(key_info, Mapping):
                continue
            if key_info.get("majorType") == 2 and isinstance(entry.get("value"), Mapping):
                signature_entry = (idx, entry)
                break

    signature_bytes: Optional[bytes] = None
    user_value: Optional[Any] = None

    if signature_entry is not None:
        idx, entry = signature_entry
        key_info = entry.get("key")
        if isinstance(key_info, Mapping):
            hex_value = key_info.get("hex")
            if isinstance(hex_value, str):
                try:
                    signature_bytes = bytes.fromhex(hex_value)
                except ValueError:
                    signature_bytes = None
        value_node = entry.get("value")
        if isinstance(value_node, Mapping):
            user_value = _structure_to_value(value_node)
        entries.pop(idx)

    repaired_value = dict(value)
    if signature_bytes is not None:
        bytes_keys = [key for key in repaired_value if isinstance(key, (bytes, bytearray))]
        for key in bytes_keys:
            repaired_value.pop(key, None)
        repaired_value[3] = signature_bytes
        sig_structure, _ = _decode_cbor_structure(cbor.encode(signature_bytes))
        if isinstance(entries, list):
            entries.append(
                {
                    "keySummary": "3",
                    "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                    "value": sig_structure,
                    "valueSummary": sig_structure.get("summary"),
                }
            )
    if user_value is not None:
        repaired_value[4] = user_value
        user_structure, _ = _decode_cbor_structure(cbor.encode(user_value))
        if isinstance(entries, list):
            entries.append(
                {
                    "keySummary": "4",
                    "key": {"majorType": 0, "type": "unsigned", "value": 4, "summary": "4"},
                    "value": user_structure,
                    "valueSummary": user_structure.get("summary"),
                }
            )
        structure["length"] = len(entries)
        structure["summary"] = f"map[{len(entries)}]"

    return structure, repaired_value, signature_bytes


def _derive_alg_from_auth_data(auth_data_bytes: Optional[bytes]) -> Optional[int]:
    if not auth_data_bytes:
        return None
    try:
        auth_data = AuthenticatorData(auth_data_bytes)
    except Exception:
        return None

    credential = getattr(auth_data, "credential_data", None)
    if credential is None:
        return None

    public_key = getattr(credential, "public_key", None)
    alg_value = getattr(public_key, "alg", None)
    return alg_value if isinstance(alg_value, int) else None


def _merge_trailing_signature(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    trailing: bytes,
) -> Optional[Tuple[Dict[str, Any], Mapping[Any, Any], bytes, bytes]]:
    if not trailing or _is_padding_bytes(trailing):
        return None

    fmt = value.get(1) or value.get("1") or value.get("fmt")
    if fmt != "packed":
        return None

    if 3 in value or "3" in value:
        return None

    if not isinstance(structure, Mapping):
        return None

    auth_data_bytes = _coerce_cbor_bytes(value.get(2) or value.get("2"))
    alg_value = _derive_alg_from_auth_data(auth_data_bytes)
    signature_bytes = bytes(trailing)

    att_stmt: Dict[str, Any] = {"sig": signature_bytes}
    if alg_value is not None:
        att_stmt["alg"] = alg_value

    att_structure, _ = _decode_cbor_structure(cbor.encode(att_stmt))

    updated_structure = dict(structure)
    entries_source = structure.get("entries")
    entries: List[Dict[str, Any]] = (
        list(entries_source) if isinstance(entries_source, list) else []
    )
    entries.append(
        {
            "keySummary": "3",
            "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
            "value": att_structure,
            "valueSummary": att_structure.get("summary") if isinstance(att_structure, Mapping) else None,
        }
    )
    updated_structure["entries"] = entries
    updated_structure["length"] = len(entries)
    updated_structure["summary"] = f"map[{len(entries)}]"

    updated_value = dict(value)
    updated_value[3] = att_stmt

    return updated_structure, updated_value, signature_bytes, b""


def _extract_mapping_string(value: Mapping[Any, Any], keys: Iterable[Any]) -> Optional[str]:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str):
            stripped = candidate.strip()
            if stripped:
                return stripped
    return None


def _extract_mapping_bytes(value: Mapping[Any, Any], keys: Iterable[Any]) -> Optional[bytes]:
    for key in keys:
        candidate = value.get(key)
        candidate_bytes = _coerce_cbor_bytes(candidate)
        if candidate_bytes is not None:
            return candidate_bytes
    return None


def _classify_ctap_map(value: Mapping[Any, Any]) -> str:
    fmt_value = _extract_mapping_string(value, (1, "1", "fmt"))
    auth_data_bytes = _extract_mapping_bytes(value, (2, "2", "authData"))
    att_stmt_value = value.get(3) or value.get("3") or value.get("attStmt")
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_value)
    att_stmt_map = att_stmt_value if isinstance(att_stmt_value, Mapping) else None

    if fmt_value is not None and auth_data_bytes is not None and (att_stmt_map is not None or att_stmt_bytes is not None):
        return "make_credential_output"

    signature_bytes = _extract_mapping_bytes(value, (3, "3", "signature"))
    if auth_data_bytes is not None and signature_bytes is not None:
        return "get_assertion_output"

    return "other"


def _summarize_bytes_for_json(data: bytes) -> Dict[str, Any]:
    return {
        "length": len(data),
        "hex": data.hex(),
        "base64": base64.b64encode(data).decode("ascii"),
        "base64url": encode_base64url(data),
    }


def _parse_authenticator_data_bytes(data: bytes) -> Tuple[Dict[str, Any], bytes, bytes]:
    details: Dict[str, Any] = {}
    if len(data) < 37:
        details["parseError"] = "Authenticator data shorter than minimum header."
        return details, data, b""

    offset = 0
    rp_id_hash = data[offset : offset + 32]
    offset += 32
    flags_byte = data[offset]
    offset += 1
    sign_count = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4

    details["rpIdHash"] = rp_id_hash.hex()
    details["flags"] = {
        "value": flags_byte,
        "bitfield": f"0b{flags_byte:08b}",
        "UP": bool(flags_byte & AuthenticatorData.FLAG.UP),
        "UV": bool(flags_byte & AuthenticatorData.FLAG.UV),
        "BE": bool(flags_byte & AuthenticatorData.FLAG.BE),
        "BS": bool(flags_byte & AuthenticatorData.FLAG.BS),
        "AT": bool(flags_byte & AuthenticatorData.FLAG.AT),
        "ED": bool(flags_byte & AuthenticatorData.FLAG.ED),
    }
    details["signCount"] = sign_count

    def _decode_cbor_item(buffer: bytes) -> Tuple[Any, int]:
        value, consumed = _lenient_decode_from(buffer, 0)
        return value, consumed

    at_flag = bool(flags_byte & AuthenticatorData.FLAG.AT)
    ed_flag = bool(flags_byte & AuthenticatorData.FLAG.ED)

    attested_trailing = b""
    if at_flag:
        attested: Dict[str, Any] = {}
        remaining = len(data) - offset
        if remaining < 18:
            attested["parseError"] = "Attested credential data truncated."
            offset = len(data)
        else:
            aaguid = data[offset : offset + 16]
            offset += 16
            declared_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2
            remaining = len(data) - offset
            actual_len = min(declared_len, remaining if remaining >= 0 else 0)
            credential_id = data[offset : offset + actual_len]
            offset += actual_len

            attested["aaguid"] = aaguid.hex()
            attested["credentialIdDeclaredLength"] = declared_len
            attested["credentialIdActualLength"] = actual_len
            attested["credentialId"] = credential_id.hex()
            if actual_len != declared_len:
                attested["lengthMismatch"] = True

            cose_raw = data[offset:]
            if cose_raw:
                try:
                    cose_value, consumed = _decode_cbor_item(cose_raw)
                except Exception:
                    cose_value, consumed = None, 0
                if consumed > 0:
                    offset += consumed
                    if isinstance(cose_value, Mapping):
                        attested["credentialPublicKey"] = _hex_json_safe(cose_value)
                    else:
                        attested["credentialPublicKey"] = _hex_json_safe(cose_value)
                    attested_trailing = cose_raw[consumed:]
                else:
                    attested["credentialPublicKey"] = cose_raw.hex()
                    offset = len(data)
            details["attestedCredentialData"] = attested

    extensions_trailing = b""
    if ed_flag and offset < len(data):
        try:
            ext_value, consumed = _decode_cbor_item(data[offset:])
        except Exception:
            ext_value, consumed = None, 0
        if consumed > 0:
            offset += consumed
            if isinstance(ext_value, Mapping):
                details["extensions"] = _hex_json_safe(ext_value)
            else:
                details["extensions"] = _hex_json_safe(ext_value)
            extensions_trailing = data[offset:]
        else:
            extensions_trailing = data[offset:]
            offset = len(data)

    trimmed = data[:offset]
    trailing = b"".join(part for part in [attested_trailing, extensions_trailing, data[offset:]] if part)
    return details, trimmed, trailing


def _format_auth_data_for_expanded_json(auth_data_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
    details, trimmed, trailing = _parse_authenticator_data_bytes(auth_data_bytes)
    formatted: Dict[str, Any] = dict(details)
    formatted.setdefault("raw", trimmed.hex())
    if trailing:
        formatted["trailingBytesHex"] = trailing.hex()
    return formatted, trailing


def _format_att_stmt_for_expanded_json(att_stmt: Any) -> Dict[str, Any]:
    formatted: Dict[str, Any] = {}

    if isinstance(att_stmt, Mapping):
        for key, value in att_stmt.items():
            if key == "sig":
                sig_bytes = _coerce_cbor_bytes(value)
                if sig_bytes is not None:
                    formatted["sig"] = sig_bytes.hex()
                else:
                    formatted["sig"] = _hex_json_safe(value)
            elif key == "x5c":
                formatted["x5c"] = _convert_certificate_chain(value)
            else:
                formatted[key] = _hex_json_safe(value)
        return formatted

    sig_bytes = _coerce_cbor_bytes(att_stmt)
    if sig_bytes is not None:
        formatted["sig"] = sig_bytes.hex()
    elif att_stmt is not None:
        formatted["value"] = _hex_json_safe(att_stmt)

    return formatted


def _decode_trailing_map(data: bytes) -> Dict[Any, Any]:
    mapping: Dict[Any, Any] = {}
    offset = 0
    while offset < len(data):
        key, new_offset = _lenient_decode_from(data, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        value, new_offset = _lenient_decode_from(data, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        try:
            mapping[key] = value
        except TypeError:
            mapping[str(key)] = value
    return mapping


def _extract_signature_from_raw_bytes(raw_bytes: bytes) -> Optional[bytes]:
    if not raw_bytes:
        return None
    hex_data = raw_bytes.hex()
    for prefix, length_hex_len in ("0358", 2), ("0359", 4), ("035a", 8), ("035b", 16):
        idx = hex_data.find(prefix)
        if idx == -1:
            continue
        length_hex = hex_data[idx + 4 : idx + 4 + length_hex_len]
        if len(length_hex) != length_hex_len:
            continue
        length = int(length_hex, 16)
        start = idx + 4 + length_hex_len
        end = start + length * 2
        if end > len(hex_data):
            continue
        try:
            return bytes.fromhex(hex_data[start:end])
        except ValueError:
            continue
    return None


def _build_make_credential_expanded_json(value: Mapping[Any, Any], raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    fmt_value = _extract_mapping_string(value, (1, "1", "fmt"))
    if fmt_value is not None:
        result["fmt"] = fmt_value

    auth_data_bytes = _extract_mapping_bytes(value, (2, "2", "authData"))
    auth_trailing = b""
    if auth_data_bytes is not None:
        auth_info, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
        result["authData"] = auth_info

    att_stmt_value = value.get(3) or value.get("3") or value.get("attStmt")
    if att_stmt_value is not None:
        result["attStmt"] = _format_att_stmt_for_expanded_json(att_stmt_value)

    optional_labels = {
        4: "epAtt",
        "epAtt": "epAtt",
        5: "largeBlobKey",
        "largeBlobKey": "largeBlobKey",
        6: "extensions",
        "extensions": "extensions",
    }
    for key, label in optional_labels.items():
        if key in value:
            result[label] = _convert_optional_ctap_field(value[key])

    for key in value:
        if key in {1, 2, 3, 4, 5, 6, "1", "2", "3", "4", "5", "6", "fmt", "authData", "attStmt"}:
            continue
        try:
            result[str(key)] = _hex_json_safe(value[key])
        except Exception:
            continue

    return result


def _build_get_assertion_expanded_json(value: Mapping[Any, Any], raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    credential_entry = value.get(1) or value.get("1") or value.get("credential")
    if credential_entry is not None:
        result["credential"] = _convert_ctap_credential_descriptor(credential_entry)

    auth_data_bytes = _extract_mapping_bytes(value, (2, "2", "authData"))
    auth_trailing = b""
    if auth_data_bytes is not None:
        auth_info, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
        result["authData"] = auth_info

    signature_bytes = _extract_mapping_bytes(value, (3, "3", "signature"))
    if signature_bytes is not None:
        result["signature"] = signature_bytes.hex()
    else:
        result["signature"] = None

    user_entry = value.get(4) or value.get("4") or value.get("user")
    if user_entry is not None:
        result["user"] = _convert_ctap_user(user_entry)

    optional_labels = {
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
        "numberOfCredentials": "numberOfCredentials",
        "userSelected": "userSelected",
        "largeBlobKey": "largeBlobKey",
        "extensions": "extensions",
    }
    for key, label in optional_labels.items():
        if key in value:
            result[label] = _convert_optional_ctap_field(value[key])

    for key in value:
        if key in {1, 2, 3, 4, 5, 6, 7, 8, "1", "2", "3", "4", "5", "6", "7", "8", "credential", "authData", "signature", "user"}:
            continue
        try:
            result[str(key)] = _hex_json_safe(value[key])
        except Exception:
            continue

    if result.get("signature") is None and auth_trailing:
        trailing_map = _decode_trailing_map(auth_trailing)
        sig_entry = trailing_map.pop(3, None)
        if sig_entry is not None:
            sig_bytes = _coerce_cbor_bytes(sig_entry)
            if sig_bytes is not None:
                result["signature"] = sig_bytes.hex()
        user_entry_trailing = trailing_map.pop(4, None)
        if user_entry_trailing is not None:
            result["user"] = _convert_ctap_user(user_entry_trailing)
        number_entry = trailing_map.pop(5, None)
        if number_entry is not None:
            result["numberOfCredentials"] = _convert_optional_ctap_field(number_entry)
        user_selected_entry = trailing_map.pop(6, None)
        if user_selected_entry is not None:
            result["userSelected"] = _convert_optional_ctap_field(user_selected_entry)
        extensions_entry = trailing_map.pop(8, None)
        if extensions_entry is not None:
            result["extensions"] = _convert_optional_ctap_field(extensions_entry)
        if trailing_map:
            result["trailingFields"] = {str(k): _hex_json_safe(v) for k, v in trailing_map.items()}

    if result.get("signature") is None and raw_bytes:
        sig_bytes = _extract_signature_from_raw_bytes(raw_bytes)
        if sig_bytes is not None:
            result["signature"] = sig_bytes.hex()

    return result


def _try_decode_cbor(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    if not data:
        return None

    ctap_info, payload = _extract_ctap_prefix(data)
    ctap_details = dict(ctap_info) if ctap_info is not None else None

    if not payload:
        decoded_payload: Dict[str, Any] = {
            "decodedValue": {"summary": "Empty CBOR payload", "byteLength": 0},
        }
        if ctap_details is not None:
            ctap_details["payloadLength"] = 0
            decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)
        return {
            "format": "CBOR",
            "inputEncoding": encoding,
            "decoded": decoded_payload,
            "binary": _binary_summary(data, encoding),
        }

    structures, values, consumed_total, remaining = _decode_cbor_sequence(payload)
    if not structures:
        return None

    base_structure = structures[0]
    base_value = values[0]
    primary_length = base_structure.get("byteLength") if isinstance(base_structure, Mapping) else None
    primary_bytes = payload[:primary_length] if isinstance(primary_length, int) and primary_length > 0 else None
    extra_structures = structures[1:]
    extra_values = values[1:]

    merged_signature: Optional[bytes] = None
    classification = "other"
    if isinstance(base_value, Mapping):
        base_structure, base_value, extra_structures, extra_values, merged_signature = _merge_ctap_make_credential(
            base_structure, base_value, extra_structures, extra_values
        )
        working_value: Mapping[Any, Any] = base_value

        fmt_candidate = _extract_mapping_string(working_value, (1, "1", "fmt"))
        auth_candidate = _extract_mapping_bytes(working_value, (2, "2", "authData"))

        if fmt_candidate is not None and auth_candidate is not None:
            temp_structure = dict(base_structure)
            entries = base_structure.get("entries")
            if isinstance(entries, list):
                temp_structure["entries"] = [dict(entry) for entry in entries]
            temp_value = dict(working_value)
            temp_structure, temp_value, repaired_sig = _repair_make_credential_entries(
                temp_structure, temp_value
            )
            att_stmt_candidate = temp_value.get(3) or temp_value.get("3")
            if isinstance(att_stmt_candidate, Mapping) and "sig" in att_stmt_candidate:
                classification = "make_credential_output"
                base_structure = temp_structure
                working_value = temp_value
                if repaired_sig is not None:
                    merged_signature = merged_signature or repaired_sig

                trailing_signature_result = _merge_trailing_signature(base_structure, working_value, remaining)
                if trailing_signature_result is not None:
                    base_structure, working_value, signature_bytes, remaining = trailing_signature_result
                    merged_signature = signature_bytes
                    consumed_total += len(signature_bytes)
                extra_structures = []
                extra_values = []
            else:
                classification = _classify_ctap_map(working_value)
        else:
            classification = _classify_ctap_map(working_value)

        if classification == "get_assertion_output":
            base_structure, working_value, assertion_sig = _repair_get_assertion_entries(
                base_structure, dict(working_value)
            )
            if assertion_sig is not None:
                merged_signature = merged_signature or assertion_sig
            extra_structures = []
            extra_values = []
        elif classification == "other" and fmt_candidate is None:
            temp_structure = dict(base_structure)
            entries = base_structure.get("entries")
            if isinstance(entries, list):
                temp_structure["entries"] = [dict(entry) for entry in entries]
            temp_value = dict(working_value)
            temp_structure, temp_value, assertion_sig = _repair_get_assertion_entries(
                temp_structure, temp_value
            )
            if assertion_sig is not None:
                classification = "get_assertion_output"
                base_structure = temp_structure
                working_value = temp_value
                merged_signature = merged_signature or assertion_sig
                extra_structures = []
                extra_values = []
        if classification == "other" and fmt_candidate is None and auth_candidate is not None:
            if ctap_details is not None and ctap_details.get("kind") == "status":
                classification = "get_assertion_output"

        base_value = working_value

    decoded_payload: Dict[str, Any] = {}

    expanded_json: Optional[Dict[str, Any]] = None
    ctap_decoded: Optional[Dict[str, Any]] = None
    hex_decoded_value: Optional[Any] = None

    if isinstance(base_value, Mapping):
        hex_decoded_value = _hex_json_safe(base_value)
        interpreted = _interpret_ctap_cbor_value(base_value)
        if interpreted is not None:
            ctap_decoded = _stringify_mapping_keys(_hex_json_safe(interpreted))

        if classification == "make_credential_output":
            expanded_json = _build_make_credential_expanded_json(base_value, primary_bytes)
        elif classification == "get_assertion_output":
            expanded_json = _build_get_assertion_expanded_json(base_value, primary_bytes)
    elif base_value is not None:
        hex_decoded_value = _hex_json_safe(base_value)

    if ctap_decoded is not None:
        decoded_payload["ctapDecoded"] = ctap_decoded

    if expanded_json:
        decoded_payload["expandedJson"] = _stringify_mapping_keys(_hex_json_safe(expanded_json))

    if ctap_decoded is None and hex_decoded_value is not None:
        decoded_payload["decodedValue"] = _stringify_mapping_keys(_hex_json_safe(hex_decoded_value))

    warnings: List[str] = []

    if ctap_details is not None:
        ctap_details["payloadLength"] = consumed_total
        if merged_signature is not None:
            ctap_details["signatureLength"] = len(merged_signature)

    if extra_values:
        warnings.append(f"Detected {len(extra_values)} additional CBOR object(s) following the primary payload.")

    trailing = remaining
    ignored_padding = 0
    if trailing:
        if _is_padding_bytes(trailing):
            ignored_padding = len(trailing)
        else:
            warnings.append(f"Trailing {len(trailing)} byte(s) after CBOR payload.")

    if ctap_details is not None:
        if ignored_padding:
            ctap_details["ignoredPaddingBytes"] = ignored_padding
        if trailing and not _is_padding_bytes(trailing):
            ctap_details["trailingBytesHex"] = trailing.hex()
        decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)

    result: Dict[str, Any] = {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": _binary_summary(data, encoding),
    }
    if warnings:
        result["malformed"] = warnings
    return result




def _interpret_ctap_cbor_value(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, Mapping):
        interpreted = _interpret_make_credential_map(value)
        if interpreted is not None:
            return {"makeCredentialResponse": interpreted}
        interpreted = _interpret_get_assertion_map(value)
        if interpreted is not None:
            return {"getAssertionResponse": interpreted}
    return None


def _interpret_make_credential_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    fmt = value.get(1)
    auth_data_bytes = _coerce_cbor_bytes(value.get(2))
    att_stmt = value.get(3)
    if not isinstance(fmt, str) or not fmt.strip() or auth_data_bytes is None or not isinstance(att_stmt, Mapping):
        return None

    interpreted: Dict[str, Any] = {}
    interpreted["1 (fmt)"] = fmt

    auth_data_details, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details
    if auth_trailing:
        trailing_map = _decode_trailing_map(auth_trailing)
        if trailing_map:
            interpreted["2 (authData trailing)"] = _hex_json_safe(trailing_map)

    if isinstance(att_stmt, Mapping):
        att_stmt_details = _convert_attestation_statement({"attestationStatement": att_stmt})
        sig_value = att_stmt.get("sig")
        sig_bytes = _coerce_cbor_bytes(sig_value)
        if sig_bytes is not None:
            att_stmt_details["sig"] = sig_bytes.hex()
        interpreted["3 (attStmt)"] = att_stmt_details
    else:
        interpreted["3 (attStmt)"] = _hex_json_safe(att_stmt)

    optional_labels = {
        4: "epAtt",
        5: "largeBlobKey",
        6: "extensions",
    }
    for key, label in optional_labels.items():
        if key in value:
            interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(value[key])

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in {1, 2, 3, 4, 5, 6}
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return interpreted


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    auth_data_bytes = _coerce_cbor_bytes(value.get(2))
    signature_bytes = _coerce_cbor_bytes(value.get(3))
    if auth_data_bytes is None:
        return None

    interpreted: Dict[str, Any] = {}

    credential_entry = value.get(1)
    if credential_entry is not None:
        interpreted["1 (credential)"] = _convert_ctap_credential_descriptor(credential_entry)

    auth_data_details, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = value.get(4)
    if user_entry is not None:
        interpreted["4 (user)"] = _convert_ctap_user(user_entry)

    optional_labels = {
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
    }
    for key, label in optional_labels.items():
        if key in value:
            interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(value[key])

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in {1, 2, 3, 4, 5, 6, 7, 8}
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    if interpreted.get("3 (signature)") is None and auth_trailing:
        trailing_map = _decode_trailing_map(auth_trailing)
        sig_entry = trailing_map.pop(3, None)
        if sig_entry is not None:
            sig_bytes = _coerce_cbor_bytes(sig_entry)
            if sig_bytes is not None:
                interpreted["3 (signature)"] = sig_bytes.hex()
        user_entry_trailing = trailing_map.pop(4, None)
        if user_entry_trailing is not None:
            interpreted["4 (user)"] = _convert_ctap_user(user_entry_trailing)
        number_entry = trailing_map.pop(5, None)
        if number_entry is not None:
            interpreted["5 (numberOfCredentials)"] = _convert_optional_ctap_field(number_entry)
        user_selected_entry = trailing_map.pop(6, None)
        if user_selected_entry is not None:
            interpreted["6 (userSelected)"] = _convert_optional_ctap_field(user_selected_entry)
        extensions_entry = trailing_map.pop(8, None)
        if extensions_entry is not None:
            interpreted["8 (extensions)"] = _convert_optional_ctap_field(extensions_entry)
        if trailing_map:
            interpreted["trailingFields"] = _hex_json_safe(trailing_map)

    return interpreted


def _convert_optional_ctap_field(value: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is not None:
        return data_bytes.hex()
    return _hex_json_safe(value)


def _convert_ctap_credential_descriptor(entry: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        return data_bytes.hex()
    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    descriptor: Dict[str, Any] = {}
    id_value = entry.get("id") or entry.get(1)
    id_bytes = _coerce_cbor_bytes(id_value)
    if id_bytes is not None:
        descriptor["id"] = id_bytes.hex()

    type_value = entry.get("type") or entry.get(2)
    if type_value is not None:
        descriptor["type"] = _hex_json_safe(type_value)

    transports_value = entry.get("transports") or entry.get(3)
    if transports_value is not None:
        descriptor["transports"] = _hex_json_safe(transports_value)

    for key in entry:
        if key in {"id", "type", "transports"} or key in {1, 2, 3}:
            continue
        descriptor[str(key)] = _hex_json_safe(entry[key])

    return descriptor


def _convert_ctap_user(entry: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        return data_bytes.hex()
    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    user: Dict[str, Any] = {}
    id_value = entry.get("id") or entry.get(1)
    id_bytes = _coerce_cbor_bytes(id_value)
    if id_bytes is not None:
        user["id"] = id_bytes.hex()

    name_value = entry.get("name") or entry.get(2)
    if name_value is not None:
        user["name"] = _hex_json_safe(name_value)

    display_name_value = entry.get("displayName") or entry.get(3)
    if display_name_value is not None:
        user["displayName"] = _hex_json_safe(display_name_value)

    icon_value = entry.get("icon") or entry.get(4)
    if icon_value is not None:
        user["icon"] = _hex_json_safe(icon_value)

    for key in entry:
        if key in {"id", "name", "displayName", "icon"} or key in {1, 2, 3, 4}:
            continue
        user[str(key)] = _hex_json_safe(entry[key])

    return user

def _describe_client_data_from_bytes(data: bytes) -> Dict[str, Any]:
    text = data.decode("utf-8")
    parsed = json.loads(text)
    details = _build_client_data_details(parsed, raw_text=text)

    try:
        client_data = CollectedClientData(data)
    except Exception:
        return details

    challenge_info = details.get("challenge")
    if isinstance(challenge_info, dict):
        challenge_info.setdefault("base64url", encode_base64url(client_data.challenge))
        challenge_info.setdefault("hex", client_data.challenge.hex())

    details.setdefault("type", client_data.type)
    details["origin"] = client_data.origin
    details["crossOrigin"] = bool(client_data.cross_origin)

    return details


def _describe_authenticator_data_bytes(data: bytes) -> Dict[str, Any]:
    auth_data = AuthenticatorData(data)
    flags = auth_data.flags

    flag_details = {
        "value": int(flags),
        "bitfield": f"0b{int(flags):08b}",
        "userPresent": bool(flags & AuthenticatorData.FLAG.UP),
        "userVerified": bool(flags & AuthenticatorData.FLAG.UV),
        "backupEligibility": bool(flags & AuthenticatorData.FLAG.BE),
        "backupState": bool(flags & AuthenticatorData.FLAG.BS),
        "attestedCredentialDataIncluded": bool(flags & AuthenticatorData.FLAG.AT),
        "extensionDataIncluded": bool(flags & AuthenticatorData.FLAG.ED),
        "flagsSet": [flag.name for flag in AuthenticatorData.FLAG if flags & flag],
    }

    details: Dict[str, Any] = {
        "rpIdHash": {
            "hex": auth_data.rp_id_hash.hex(),
            "base64url": encode_base64url(auth_data.rp_id_hash),
        },
        "flags": flag_details,
        "signCount": auth_data.counter,
    }

    credential_data = auth_data.credential_data
    if credential_data is not None:
        details["attestedCredentialData"] = {
            "aaguid": str(credential_data.aaguid),
            "aaguidHex": credential_data.aaguid.hex(),
            "credentialId": _binary_summary(credential_data.credential_id, "binary"),
            "publicKey": make_json_safe(dict(credential_data.public_key)),
        }

    extensions = auth_data.extensions
    if extensions is not None:
        extensions_payload: Dict[str, Any] = {
            "raw": make_json_safe(extensions),
        }
        if isinstance(extensions, Mapping):
            extensions_payload["summary"] = make_json_safe(
                summarize_authenticator_extensions(extensions)
            )
        details["extensions"] = extensions_payload

    return details


def _parse_attestation_object(data: bytes) -> Dict[str, Any]:
    attestation = AttestationObject(data)
    details: Dict[str, Any] = {
        "attestationFormat": attestation.fmt,
        "attestationStatement": make_json_safe(attestation.att_stmt),
        "authenticatorData": _describe_authenticator_data_bytes(bytes(attestation.auth_data)),
        "cbor": make_json_safe(cbor.decode(data)),
    }

    certificate_details = _extract_attestation_certificate(attestation.att_stmt)
    if certificate_details is not None:
        details["attestationCertificate"] = certificate_details

    return details


def _extract_attestation_certificate(att_stmt: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(att_stmt, Mapping):
        return None

    chain = att_stmt.get("x5c")
    if not isinstance(chain, Sequence) or not chain:
        return None

    first_entry = chain[0]
    cert_bytes: Optional[bytes]

    if isinstance(first_entry, str):
        cleaned = "".join(first_entry.split())
        padding = (-len(cleaned)) % 4
        try:
            cert_bytes = base64.b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            cert_bytes = None
    else:
        try:
            cert_bytes = bytes(first_entry)
        except Exception:
            cert_bytes = None

    if not cert_bytes:
        return None

    try:
        return serialize_attestation_certificate(cert_bytes)
    except Exception:
        return None


def _build_client_data_details(
    parsed: Mapping[str, Any], raw_text: Optional[str] = None
) -> Dict[str, Any]:
    details: Dict[str, Any] = {}

    type_value = parsed.get("type")
    if type_value is not None:
        details["type"] = type_value

    challenge_value = parsed.get("challenge")
    if challenge_value is not None:
        challenge_info: Dict[str, Any] = {"raw": challenge_value}
        if isinstance(challenge_value, str):
            try:
                challenge_bytes, challenge_encoding = _decode_binary_input(challenge_value)
            except ValueError:
                pass
            else:
                challenge_info.update(_binary_summary(challenge_bytes, challenge_encoding))
        details["challenge"] = challenge_info
    else:
        details["challenge"] = None

    origin_value = parsed.get("origin")
    if origin_value is not None:
        details["origin"] = origin_value

    cross_origin = parsed.get("crossOrigin")
    if cross_origin is not None:
        details["crossOrigin"] = bool(cross_origin)

    token_binding = parsed.get("tokenBinding")
    if token_binding is not None:
        details["tokenBinding"] = token_binding

    details["rawJson"] = parsed
    if raw_text is not None:
        details["rawText"] = raw_text

    return details


def _binary_summary(data: bytes, encoding: Optional[str] = None) -> Dict[str, Any]:
    summary = {
        "length": len(data),
        "base64": base64.b64encode(data).decode("ascii"),
        "base64url": encode_base64url(data),
        "hex": data.hex(),
        "colonHex": colon_hex(data),
    }
    if encoding:
        summary["encoding"] = encoding
    return summary


def _try_decode_utf8(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_public_key_credential(value: Mapping[str, Any]) -> bool:
    response = value.get("response")
    if not isinstance(response, Mapping):
        return False

    if not value.get("type") and not value.get("id"):
        return False

    return any(
        field in response
        for field in ("attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle")
    )


def _is_client_data_dict(value: Mapping[str, Any]) -> bool:
    if not isinstance(value.get("type"), str):
        return False
    if "challenge" not in value:
        return False
    return isinstance(value.get("origin"), str)


def _prepare_decoder_response(result: Dict[str, Any]) -> Dict[str, Any]:
    return _build_decoder_payload(result)


def _build_decoder_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    base_type = _base_type(result.get("format"))
    data = _convert_result_to_data(base_type, result)
    malformed = result.get("malformed")
    if not isinstance(malformed, list):
        malformed = []

    type_label = base_type
    if base_type == "CBOR":
        decoded = result.get("decoded")
        qualifiers: List[str] = []
        if isinstance(decoded, Mapping):
            ctap_info = decoded.get("ctap")
            if isinstance(ctap_info, Mapping):
                meaning = ctap_info.get("meaning") or ctap_info.get("description")
                if isinstance(meaning, str) and meaning:
                    qualifiers.append(meaning)
            ctap_decoded = decoded.get("ctapDecoded")
            if isinstance(ctap_decoded, Mapping):
                if "makeCredentialResponse" in ctap_decoded:
                    qualifiers.append("MakeCredential response")
                if "getAssertionResponse" in ctap_decoded:
                    qualifiers.append("GetAssertion response")
            expanded_json = decoded.get("expandedJson")
            if isinstance(expanded_json, Mapping):
                if "attStmt" in expanded_json and "MakeCredential response" not in qualifiers:
                    qualifiers.append("MakeCredential response")
                if "signature" in expanded_json and "GetAssertion response" not in qualifiers:
                    qualifiers.append("GetAssertion response")
        if qualifiers:
            unique = []
            for qualifier in qualifiers:
                if qualifier not in unique:
                    unique.append(qualifier)
            type_label = f"{base_type} ({'; '.join(unique)})"

    return {
        "success": True,
        "type": type_label,
        "data": data,
        "malformed": malformed,
    }


def _convert_result_to_data(base_type: str, result: Dict[str, Any]) -> Any:
    if base_type == "PublicKeyCredential":
        return _convert_public_key_credential_data(result)
    if base_type == "Attestation object":
        return _convert_attestation_object_data(result)
    if base_type == "Authenticator data":
        return _convert_authenticator_data_result(result)
    if base_type == "WebAuthn client data":
        return _convert_client_data_result(result)
    if base_type == "X.509 certificate":
        return _convert_certificate_result(result)
    if base_type == "JSON":
        return {"json": make_json_safe(result.get("decoded"))}
    if base_type == "CBOR":
        decoded = result.get("decoded")
        if isinstance(decoded, Mapping):
            payload: Dict[str, Any] = {}
            if "ctapDecoded" in decoded:
                payload["ctapDecoded"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["ctapDecoded"])
                )
            if "expandedJson" in decoded:
                payload["expandedJson"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["expandedJson"])
                )
            if "decodedValue" in decoded:
                payload["decodedValue"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["decodedValue"])
                )
            if "ctap" in decoded:
                payload["ctap"] = _stringify_mapping_keys(make_json_safe(decoded["ctap"]))
            if not payload:
                payload["cbor"] = make_json_safe(decoded)
            return payload
        return {"cbor": make_json_safe(decoded)}

    decoded_value = result.get("decoded")
    if decoded_value is not None:
        return make_json_safe(decoded_value)
    binary_value = result.get("binary")
    if binary_value is not None:
        return make_json_safe(binary_value)
    return {}


def _convert_public_key_credential_data(result: Mapping[str, Any]) -> Dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}

    payload: Dict[str, Any] = {}

    credential_overview = _build_credential_overview(decoded)
    if credential_overview:
        payload["credential"] = credential_overview

    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    attestation_section = _convert_attestation_entry(attestation_entry)
    if attestation_section:
        payload["attestationObject"] = attestation_section

    authenticator_section = _build_authenticator_section(
        response, attestation_entry, attestation_section
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_data_section = _convert_client_data_entry(
        response.get("clientDataJSON") if isinstance(response, Mapping) else None
    )
    if client_data_section:
        payload["clientDataJSON"] = client_data_section

    client_extensions = decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None
    if client_extensions is not None:
        payload["clientExtensionResults"] = make_json_safe(client_extensions)

    response_extras = _collect_response_extras(response)
    if response_extras:
        payload["responseDetails"] = response_extras

    return payload


def _convert_attestation_object_data(result: Mapping[str, Any]) -> Dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    attestation_section = _convert_attestation_entry(decoded)
    payload: Dict[str, Any] = {}
    if attestation_section:
        if "raw" not in attestation_section:
            binary_info = result.get("binary") if isinstance(result.get("binary"), Mapping) else None
            if isinstance(binary_info, Mapping):
                raw_value = binary_info.get("base64") or binary_info.get("base64url")
                if raw_value:
                    attestation_section["raw"] = raw_value
        payload["attestationObject"] = attestation_section

    authenticator_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None
    authenticator_section = _build_authenticator_data_payload(
        _extract_authenticator_bytes_from_attestation(decoded),
        authenticator_details,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if client_extensions:
        payload["extensions"] = make_json_safe(client_extensions)

    return payload


def _convert_authenticator_data_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    binary_entry = result.get("binary")
    auth_bytes = _extract_bytes_from_binary(result.get("binary"))
    if auth_bytes is None:
        auth_bytes = _extract_bytes_from_binary(decoded)
    authenticator_section = _build_authenticator_data_payload(
        auth_bytes,
        decoded,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    return authenticator_section or {}


def _convert_client_data_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    return _convert_client_data_entry(decoded) or {}


def _convert_certificate_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    if not decoded:
        return {}

    if "certificates" in decoded and isinstance(decoded["certificates"], list):
        certificates = [
            _convert_certificate_payload(entry) for entry in decoded["certificates"] if isinstance(entry, Mapping)
        ]
        return {"certificates": [cert for cert in certificates if cert]}

    certificate_payload = _convert_certificate_payload(decoded)
    return certificate_payload or {}


def _build_credential_overview(decoded: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(decoded, Mapping):
        return {}

    overview: Dict[str, Any] = {}
    for key in ("id", "type", "authenticatorAttachment"):
        value = decoded.get(key)
        if value is not None:
            overview[key] = value

    transports = decoded.get("transports")
    if transports is not None:
        overview["transports"] = make_json_safe(transports)

    raw_id = decoded.get("rawId")
    if isinstance(raw_id, Mapping):
        raw_payload: Dict[str, Any] = {}
        raw_value = raw_id.get("raw")
        if raw_value is not None:
            raw_payload["raw"] = raw_value
        binary = raw_id.get("binary")
        if binary is not None:
            raw_payload["binary"] = make_json_safe(binary)
        if raw_payload:
            overview["rawId"] = raw_payload
    elif raw_id is not None:
        overview["rawId"] = raw_id

    raw_json = decoded.get("rawJson")
    if isinstance(raw_json, str) and raw_json.strip():
        overview["rawJson"] = raw_json

    return overview


def _convert_attestation_entry(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    payload: Dict[str, Any] = {}

    fmt = None
    if isinstance(details, Mapping):
        fmt = details.get("attestationFormat") or details.get("fmt")
        cbor_section = details.get("cbor") if isinstance(details.get("cbor"), Mapping) else None
        if fmt is None and isinstance(cbor_section, Mapping):
            fmt = cbor_section.get("fmt")
    if fmt:
        payload["fmt"] = fmt

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        payload["raw"] = raw_value

    att_stmt = _convert_attestation_statement(details)
    if att_stmt:
        if "x5c" in att_stmt and not att_stmt["x5c"]:
            certificate_detail = None
            if isinstance(details, Mapping):
                certificate_detail = details.get("attestationCertificate")
                if certificate_detail is None:
                    certificates_list = details.get("attestationCertificates")
                    if isinstance(certificates_list, list) and certificates_list:
                        certificate_detail = certificates_list[0]
            if certificate_detail is not None:
                converted = _convert_certificate_payload(certificate_detail)
                if converted:
                    att_stmt["x5c"] = [converted]
        payload["attStmt"] = att_stmt

    return payload


def _convert_attestation_statement(details: Any) -> Dict[str, Any]:
    if not isinstance(details, Mapping):
        return {}

    statement = details.get("attestationStatement") if isinstance(details.get("attestationStatement"), Mapping) else None
    if statement is None:
        cbor_section = details.get("cbor") if isinstance(details.get("cbor"), Mapping) else None
        if isinstance(cbor_section, Mapping):
            possible = cbor_section.get("attStmt")
            if isinstance(possible, Mapping):
                statement = possible

    if not isinstance(statement, Mapping):
        return {}

    payload: Dict[str, Any] = {}
    for key, value in statement.items():
        if key == "x5c":
            payload["x5c"] = _convert_certificate_chain(value)
        else:
            payload[key] = _hex_json_safe(value)
    return payload


def _convert_certificate_chain(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []

    certificates: List[Dict[str, Any]] = []
    for item in value:
        cert_payload = _convert_certificate_bytes(item)
        if cert_payload:
            certificates.append(cert_payload)
    return certificates


def _convert_certificate_bytes(value: Any) -> Dict[str, Any]:
    cert_bytes: Optional[bytes] = None
    if isinstance(value, (bytes, bytearray)):
        cert_bytes = bytes(value)
    elif isinstance(value, str):
        cleaned = "".join(value.split())
        padding = (-len(cleaned)) % 4
        try:
            cert_bytes = base64.b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            cert_bytes = None
    elif isinstance(value, Mapping):
        return _convert_certificate_payload(value)

    if cert_bytes is None:
        return {}

    parsed = serialize_attestation_certificate(cert_bytes)
    if not isinstance(parsed, Mapping):
        return {}

    parsed_copy = dict(parsed)
    parsed_copy["derBase64"] = parsed.get("derBase64") or base64.b64encode(cert_bytes).decode("ascii")
    parsed_copy.setdefault("pem", parsed.get("pem"))
    return _convert_certificate_payload(parsed_copy, cert_bytes)


def _convert_certificate_payload(
    entry: Mapping[str, Any], cert_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    payload: Dict[str, Any] = {}

    if cert_bytes is None:
        der_base64 = entry.get("derBase64")
        if isinstance(der_base64, str):
            try:
                cert_bytes = base64.b64decode(der_base64)
            except (ValueError, binascii.Error):
                cert_bytes = None

    if cert_bytes is not None:
        payload["raw"] = cert_bytes.hex()

    pem_value = entry.get("pem")
    if isinstance(pem_value, str) and pem_value.strip():
        payload["pem"] = pem_value

    parsed_entry = {key: value for key, value in entry.items() if key != "summary"}
    payload["parsedX5c"] = _hex_json_safe(parsed_entry)

    return payload


def _build_authenticator_section(
    response: Any,
    attestation_entry: Any,
    attestation_section: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    response_mapping = response if isinstance(response, Mapping) else {}
    attestation_mapping = attestation_entry if isinstance(attestation_entry, Mapping) else {}

    auth_bytes = _extract_authenticator_bytes(response_mapping, attestation_entry)

    details = None
    auth_entry = response_mapping.get("authenticatorData")
    if isinstance(auth_entry, Mapping):
        details = auth_entry.get("details")
    if details is None and isinstance(attestation_mapping.get("details"), Mapping):
        details = attestation_mapping["details"].get("authenticatorData")

    fallback_alg = None
    if isinstance(response_mapping, Mapping):
        fallback_alg = response_mapping.get("publicKeyAlgorithm")

    return _build_authenticator_data_payload(auth_bytes, details, fallback_alg)


def _build_authenticator_data_payload(
    auth_bytes: Optional[bytes],
    details: Any,
    fallback_alg: Optional[Any] = None,
) -> Dict[str, Any]:
    if auth_bytes is None and not isinstance(details, Mapping):
        return {}

    payload: Dict[str, Any] = {}

    if auth_bytes is not None:
        payload["raw"] = auth_bytes.hex()

    rp_hash_hex = None
    if isinstance(details, Mapping):
        rp_info = details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hash_hex = rp_info.get("hex") or rp_info.get("value")
        elif isinstance(rp_info, str):
            rp_hash_hex = rp_info
    if rp_hash_hex is None and auth_bytes is not None and len(auth_bytes) >= 32:
        rp_hash_hex = auth_bytes[:32].hex()
    if rp_hash_hex:
        payload["rpIdHash"] = rp_hash_hex

    flags_info = details.get("flags") if isinstance(details, Mapping) else None
    flags_byte = auth_bytes[32] if auth_bytes is not None and len(auth_bytes) > 32 else None
    flags_payload = _build_flag_payload(flags_info, flags_byte)
    if flags_payload:
        payload["flags"] = flags_payload

    counter_value = None
    if isinstance(details, Mapping):
        counter_value = details.get("signCount")
    if counter_value is None and auth_bytes is not None and len(auth_bytes) >= 37:
        counter_value = int.from_bytes(auth_bytes[33:37], "big")
    if counter_value is not None:
        try:
            payload["counter"] = int(counter_value)
        except (TypeError, ValueError):
            payload["counter"] = counter_value

    credential_details = details.get("attestedCredentialData") if isinstance(details, Mapping) else None
    credential_payload = _build_credential_payload(credential_details, auth_bytes, fallback_alg)
    if credential_payload:
        payload["credential"] = credential_payload

    extensions = details.get("extensions") if isinstance(details, Mapping) else None
    if extensions is not None:
        payload["extensions"] = make_json_safe(extensions)

    return payload


def _build_flag_payload(flag_details: Any, flags_byte: Optional[int]) -> Dict[str, Any]:
    if flag_details is None and flags_byte is None:
        return {}

    payload: Dict[str, Any] = {}

    bitfield = None
    hex_value = None
    up = uv = be = bs = at = ed = None

    if isinstance(flag_details, Mapping):
        bitfield = flag_details.get("bitfield")
        value = flag_details.get("value")
        try:
            hex_value = f"{int(value):02x}".upper()
        except (TypeError, ValueError):
            hex_value = None
        up = flag_details.get("userPresent")
        uv = flag_details.get("userVerified")
        be = flag_details.get("backupEligible")
        bs = flag_details.get("backupState")
        at = flag_details.get("attestedCredentialData")
        ed = flag_details.get("extensionData")
        if flags_byte is None:
            try:
                flags_byte = int(value)
            except (TypeError, ValueError):
                flags_byte = None

    if flags_byte is not None:
        if bitfield is None:
            bitfield = f"{flags_byte:08b}"
        if hex_value is None:
            hex_value = f"{flags_byte:02x}".upper()
        if up is None:
            up = bool(flags_byte & 0x01)
        if uv is None:
            uv = bool(flags_byte & 0x04)
        if be is None:
            be = bool(flags_byte & 0x08)
        if bs is None:
            bs = bool(flags_byte & 0x10)
        if at is None:
            at = bool(flags_byte & 0x40)
        if ed is None:
            ed = bool(flags_byte & 0x80)

    if bitfield:
        payload["bin"] = bitfield.replace("0b", "")[-8:].zfill(8)
    if hex_value:
        payload["hex"] = hex_value
        payload["raw"] = hex_value
    if up is not None:
        payload["UP"] = bool(up)
    if uv is not None:
        payload["UV"] = bool(uv)
    if be is not None:
        payload["BE"] = bool(be)
    if bs is not None:
        payload["BS"] = bool(bs)
    if at is not None:
        payload["AT"] = bool(at)
    if ed is not None:
        payload["ED"] = bool(ed)

    return payload


def _build_credential_payload(
    credential_details: Any,
    auth_bytes: Optional[bytes],
    fallback_alg: Optional[Any] = None,
) -> Dict[str, Any]:
    if credential_details is None and auth_bytes is None:
        return {}

    aaguid_hex = None
    aaguid_uuid = None
    credential_id_hex = None
    credential_id_length = None
    cose_key: Optional[Mapping[str, Any]] = None

    if isinstance(credential_details, Mapping):
        aaguid_uuid = credential_details.get("aaguid")
        aaguid_hex = credential_details.get("aaguidHex")
        credential_id_info = credential_details.get("credentialId")
        if isinstance(credential_id_info, Mapping):
            credential_id_hex = credential_id_info.get("hex")
            length_value = credential_id_info.get("length")
            try:
                credential_id_length = f"{int(length_value):04x}".upper()
            except (TypeError, ValueError):
                if isinstance(length_value, str):
                    credential_id_length = length_value
        public_key_info = credential_details.get("publicKey")
        if isinstance(public_key_info, Mapping):
            cose_key = public_key_info

    attested_raw_hex = None
    public_key_raw_hex = None
    if auth_bytes is not None and len(auth_bytes) > 37:
        attested_bytes = auth_bytes[37:]
        attested_raw_hex = attested_bytes.hex()
        if len(attested_bytes) >= 18:
            aaguid_bytes = attested_bytes[:16]
            length_bytes = attested_bytes[16:18]
            cred_length = int.from_bytes(length_bytes, "big")
            credential_bytes = attested_bytes[18 : 18 + cred_length]
            public_key_bytes = attested_bytes[18 + cred_length :]
            if not aaguid_hex:
                aaguid_hex = aaguid_bytes.hex()
            if not aaguid_uuid:
                try:
                    aaguid_uuid = str(uuid.UUID(bytes=aaguid_bytes))
                except Exception:
                    aaguid_uuid = None
            if credential_id_hex is None:
                credential_id_hex = credential_bytes.hex()
            if credential_id_length is None:
                credential_id_length = f"{cred_length:04x}".upper()
            if public_key_bytes:
                public_key_raw_hex = public_key_bytes.hex()

    public_key_payload: Dict[str, Any] = {}
    if cose_key is not None:
        cose_display = _convert_cose_key_for_display(cose_key)
        public_key_payload["cose"] = make_json_safe(cose_display)
        alg_label = _resolve_cose_algorithm(cose_key, fallback_alg)
    else:
        alg_label = _resolve_cose_algorithm({}, fallback_alg)
    if alg_label is not None:
        public_key_payload["alg"] = alg_label
    if public_key_raw_hex:
        public_key_payload["raw"] = public_key_raw_hex
    if not public_key_payload:
        public_key_payload = {}

    credential_payload: Dict[str, Any] = {}
    if attested_raw_hex:
        credential_payload["raw"] = attested_raw_hex
    if aaguid_hex or aaguid_uuid:
        aaguid_payload: Dict[str, Any] = {}
        if aaguid_hex:
            aaguid_payload["raw"] = aaguid_hex
        if aaguid_uuid:
            aaguid_payload["uuid"] = aaguid_uuid
        credential_payload["aaguid"] = aaguid_payload
    if credential_id_length:
        credential_payload["credentialIdLength"] = credential_id_length
    if credential_id_hex:
        credential_payload["credentialId"] = credential_id_hex
    if public_key_payload:
        credential_payload["publicKey"] = public_key_payload

    return credential_payload


def _convert_client_data_entry(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    if not isinstance(details, Mapping):
        return {}

    payload: Dict[str, Any] = {}
    for key in ("type", "origin", "crossOrigin"):
        if key in details:
            payload[key] = make_json_safe(details.get(key))

    challenge_info = details.get("challenge")
    if isinstance(challenge_info, Mapping):
        challenge_value = (
            challenge_info.get("raw")
            or challenge_info.get("base64url")
            or challenge_info.get("base64")
        )
        if challenge_value is not None:
            payload["challenge"] = challenge_value
        else:
            payload["challenge"] = make_json_safe(challenge_info)
    elif details.get("challenge") is not None:
        payload["challenge"] = details.get("challenge")

    return payload


def _collect_response_extras(response: Any) -> Dict[str, Any]:
    if not isinstance(response, Mapping):
        return {}

    extras: Dict[str, Any] = {}
    for field in ("signature", "userHandle", "publicKey", "publicKeyAlgorithm"):
        if field in response and response[field] is not None:
            extras[field] = make_json_safe(response[field])

    return extras


def _format_result_summary(result: Dict[str, Any]) -> str:
    base_type = _base_type(result.get("format"))
    formatter = {
        "PublicKeyCredential": _format_public_key_credential_summary,
        "Attestation object": _format_attestation_object_summary,
        "Authenticator data": _format_authenticator_data_summary,
        "WebAuthn client data": _format_client_data_summary,
        "X.509 certificate": _format_certificate_summary,
        "JSON": _format_json_summary,
        "CBOR": _format_cbor_summary,
    }.get(base_type, _format_generic_summary)

    lines = formatter(result)
    return "\n".join(line for line in lines if line is not None).rstrip()


def _base_type(format_label: Optional[str]) -> str:
    if not format_label:
        return "Decoded data"
    separator = format_label.find(" (")
    if separator != -1:
        return format_label[:separator]
    return format_label


def _format_public_key_credential_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}
    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    authenticator_entry = response.get("authenticatorData") if isinstance(response, Mapping) else None

    attestation_details = attestation_entry.get("details") if isinstance(attestation_entry, Mapping) else None
    auth_details = None
    if isinstance(attestation_details, Mapping):
        auth_details = attestation_details.get("authenticatorData")
    if auth_details is None and isinstance(authenticator_entry, Mapping):
        auth_details = authenticator_entry.get("details")

    auth_bytes = _extract_authenticator_bytes(response, attestation_entry)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, auth_details, auth_bytes, response)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None)
    _extend_with_attestation_section(
        lines, attestation_entry, attestation_details, include_certificates=False
    )
    _extend_with_client_data_entry(lines, response.get("clientDataJSON") if isinstance(response, Mapping) else None)
    return lines


def _format_attestation_object_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None

    lines: List[str] = [f"Detected type:\t{base_type}"]
    attestation_entry: Dict[str, Any] = {"binary": result.get("binary")} if result.get("binary") else {}
    auth_bytes = _extract_authenticator_bytes_from_attestation(attestation_entry)
    _extend_with_authenticator_details(lines, auth_details, auth_bytes)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, None)
    _extend_with_attestation_section(
        lines, attestation_entry, decoded, include_certificates=False
    )
    return lines


def _format_authenticator_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_bytes = _extract_bytes_from_binary(result.get("binary"))

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, decoded, auth_bytes)
    _extend_with_authenticator_extensions(lines, decoded)
    _extend_with_client_extensions(lines, None)
    return lines


def _format_client_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_client_data_details(lines, decoded)
    return lines


def _format_certificate_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    certificate_lines = _build_certificate_summary_lines(decoded)
    if not certificate_lines:
        certificate_lines = _format_json_block(decoded)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _append_multiline_field(
        lines,
        "Certificate",
        certificate_lines,
        indent_str="",
        force_multiline=True,
    )
    return lines


def _format_json_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded")
    json_lines = _format_json_block(decoded)
    lines: List[str] = ["Detected type:\tJSON"]
    _append_multiline_field(lines, "JSON", json_lines, indent_str="  ")
    return lines


def _format_cbor_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    decoded_value = decoded.get("decodedValue") if isinstance(decoded, Mapping) else None
    expanded_json = decoded.get("expandedJson") if isinstance(decoded, Mapping) else None
    ctap_info = decoded.get("ctap") if isinstance(decoded, Mapping) else None
    ctap_decoded = decoded.get("ctapDecoded") if isinstance(decoded, Mapping) else None

    lines: List[str] = ["Detected type:\tCBOR"]

    if isinstance(ctap_info, Mapping):
        meaning = ctap_info.get("meaning") or ctap_info.get("description")
        if isinstance(meaning, str) and meaning:
            lines[0] = f"Detected type:\tCBOR ({meaning})"
        code_hex = ctap_info.get("codeHex")
        code_value = code_hex or ctap_info.get("code")
        _append_simple_field(lines, "CTAP code", code_value)
        category = ctap_info.get("kind") or ctap_info.get("category")
        _append_simple_field(lines, "CTAP type", category)
        payload_length = ctap_info.get("payloadLength")
        if payload_length is not None:
            _append_simple_field(lines, "CBOR payload length", payload_length)

    if isinstance(ctap_decoded, Mapping) and ctap_decoded:
        response_labels: List[str] = []
        if "makeCredentialResponse" in ctap_decoded:
            response_labels.append("MakeCredential response")
        if "getAssertionResponse" in ctap_decoded:
            response_labels.append("GetAssertion response")
        if response_labels:
            lines.append(f"CTAP interpretation:\t{', '.join(response_labels)}")
        interpreted_lines = _format_json_block(ctap_decoded)
        _append_multiline_field(lines, "CTAP decoded", interpreted_lines, indent_str="  ")

    if isinstance(expanded_json, Mapping):
        expanded_lines = _format_json_block(expanded_json)
        _append_multiline_field(lines, "Expanded JSON", expanded_lines, indent_str="  ")

    if decoded_value is not None:
        value_lines = _format_json_block(decoded_value)
        _append_multiline_field(lines, "Decoded value", value_lines, indent_str="  ")
    elif decoded and not expanded_json and not ctap_decoded:
        json_lines = _format_json_block(decoded)
        _append_multiline_field(lines, "CBOR", json_lines, indent_str="  ")

    return lines


def _format_generic_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    lines: List[str] = [f"Detected type:\t{base_type}"]

    decoded = result.get("decoded")
    if decoded is not None:
        _append_multiline_field(lines, "Decoded", _format_json_block(decoded), indent_str="  ")
    else:
        binary = result.get("binary")
        if binary is not None:
            _append_multiline_field(lines, "Binary", _format_json_block(binary), indent_str="  ")

    return lines


_DEVICE_IDENTIFIER_NAMES: Dict[str, str] = {
    "1.3.6.1.4.1.41482.1.1": "Security Key by Yubico Series",
}


def _build_certificate_summary_lines(decoded: Any) -> List[str]:
    if not isinstance(decoded, Mapping):
        return []

    lines: List[str] = []

    version = decoded.get("version")
    if isinstance(version, Mapping):
        display = version.get("display")
        if display:
            lines.append(f"Version: {display}")

    serial = decoded.get("serialNumber")
    if isinstance(serial, Mapping):
        decimal = serial.get("decimal")
        hex_value = serial.get("hex")
        if decimal and hex_value:
            lines.append(f"Certificate Serial Number: {decimal} ({hex_value})")
        elif decimal:
            lines.append(f"Certificate Serial Number: {decimal}")

    signature_algorithm = decoded.get("signatureAlgorithm")
    if signature_algorithm:
        lines.append(f"Signature Algorithm: {signature_algorithm}")

    issuer = decoded.get("issuer")
    if issuer:
        lines.append(f"Issuer: {issuer}")

    validity = decoded.get("validity")
    if isinstance(validity, Mapping):
        not_before = _format_certificate_time(validity.get("notBefore"))
        not_after = _format_certificate_time(validity.get("notAfter"))
        if not_before or not_after:
            lines.append("Validity")
            if not_before:
                lines.append(f"Not Before: {not_before}")
            if not_after:
                lines.append(f"Not After: {not_after}")

    subject = decoded.get("subject")
    if subject:
        lines.append(f"Subject: {subject}")

    lines.extend(_build_subject_public_key_info_lines(decoded.get("publicKeyInfo")))
    lines.extend(_build_certificate_extensions_lines(decoded.get("extensions")))
    lines.extend(_build_signature_lines(decoded.get("signature")))
    lines.extend(_build_fingerprint_lines(decoded.get("fingerprints")))

    ski_lines = _build_subject_key_identifier_lines(decoded)
    if ski_lines:
        lines.append("Subject key identifier:")
        lines.extend(ski_lines)

    return [line for line in lines if line is not None]


def _format_certificate_time(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        normalized = text.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            return text
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        return timestamp.isoformat()
    return None


def _build_subject_public_key_info_lines(info: Any) -> List[str]:
    if not isinstance(info, Mapping):
        return []

    lines: List[str] = ["Subject Public Key Info:"]

    key_type = info.get("type")
    if key_type:
        lines.append(f"Type: {key_type}")

    key_size = info.get("keySize")
    if isinstance(key_size, int):
        lines.append(f"Public-Key: ({key_size} bit)")

    point_lines = _format_public_key_point_lines(info.get("uncompressedPoint"))
    if point_lines:
        lines.append("pub:")
        lines.extend(point_lines)

    curve = info.get("curve")
    if not curve and isinstance(info.get("algorithm"), Mapping):
        curve = info["algorithm"].get("namedCurve")
    if curve:
        lines.append(f"Curve: {curve}")

    return [line for line in lines if line]


def _format_public_key_point_lines(point: Any) -> List[str]:
    if isinstance(point, str) and point.strip():
        return format_hex_string_lines(point)
    return []


def _build_certificate_extensions_lines(extensions: Any) -> List[str]:
    if not isinstance(extensions, list) or not extensions:
        return []

    lines: List[str] = ["X509v3 extensions:"]
    for extension in extensions:
        if not isinstance(extension, Mapping):
            continue
        header = _format_certificate_extension_header(extension)
        if header:
            lines.append(f"{header}:")
        value_lines = _format_certificate_extension_value(extension.get("value"))
        lines.extend(value_lines)
    return lines


def _format_certificate_extension_header(extension: Mapping[str, Any]) -> Optional[str]:
    display_header = extension.get("displayHeader")
    if isinstance(display_header, str) and display_header.strip():
        return display_header.strip()

    include_oid = extension.get("includeOidInHeader", True)
    oid = extension.get("oid")
    friendly = extension.get("friendlyName") or extension.get("name")

    parts: List[str] = []
    if include_oid and oid:
        parts.append(str(oid))
    if friendly and friendly != oid:
        friendly_part = f"({friendly})" if include_oid and parts else str(friendly)
        parts.append(friendly_part)

    if not parts:
        if oid:
            parts.append(str(oid))
        elif friendly:
            parts.append(str(friendly))
        else:
            return None

    return " ".join(parts)


def _format_certificate_extension_value(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, Mapping):
        lines: List[str] = []
        hex_value = None
        device_identifier = None

        for key, entry in value.items():
            if entry in (None, ""):
                continue
            key_lower = str(key).lower()
            if key_lower == "hex value":
                hex_value = str(entry)
            elif key_lower == "device identifier":
                device_identifier = entry
            elif isinstance(entry, (Mapping, list, tuple)):
                lines.append(f"{key}:")
                lines.extend(_format_certificate_extension_value(entry))
            else:
                lines.append(f"{key}: {entry}")

        ordered: List[str] = []
        if hex_value is not None:
            ordered.append(f"Hex value: {hex_value}")
        if device_identifier is not None:
            ordered.append(_format_device_identifier_line(device_identifier))
        ordered.extend(lines)
        return ordered

    if isinstance(value, (list, tuple)):
        lines: List[str] = []
        for item in value:
            if item in (None, ""):
                continue
            if isinstance(item, (Mapping, list, tuple)):
                lines.extend(_format_certificate_extension_value(item))
            else:
                lines.append(str(item))
        return lines

    return [str(value)]


def _format_device_identifier_line(identifier: Any) -> str:
    if not isinstance(identifier, str):
        return str(identifier)
    cleaned = identifier.strip()
    friendly = _DEVICE_IDENTIFIER_NAMES.get(cleaned)
    return f"{cleaned} ({friendly})" if friendly else cleaned


def _build_signature_lines(signature: Any) -> List[str]:
    if not isinstance(signature, Mapping):
        return []

    lines: List[str] = []
    algorithm = signature.get("algorithm")
    if algorithm:
        lines.append(f"Signature Algorithm: {algorithm}")

    hex_lines: List[str]
    signature_lines = signature.get("lines")
    if isinstance(signature_lines, list) and signature_lines:
        hex_lines = [line for line in signature_lines if line]
    else:
        hex_value = signature.get("hex")
        if isinstance(hex_value, str) and hex_value.strip():
            hex_lines = format_hex_string_lines(hex_value)
        else:
            hex_lines = []

    lines.extend(hex_lines)
    return lines


def _build_fingerprint_lines(fingerprints: Any) -> List[str]:
    if not isinstance(fingerprints, Mapping):
        return []

    ordered: List[Tuple[str, List[str]]] = []
    for label in ("md5", "sha1", "sha256"):
        value = fingerprints.get(label)
        if isinstance(value, str) and value.strip():
            ordered.append((label.upper(), format_hex_string_lines(value)))

    if not ordered:
        return []

    lines: List[str] = ["Fingerprint:"]
    for name, hex_lines in ordered:
        lines.append(f"{name}:")
        lines.extend(hex_lines)
    return lines


def _build_subject_key_identifier_lines(decoded: Mapping[str, Any]) -> List[str]:
    extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if isinstance(extensions, list):
        for extension in extensions:
            if not isinstance(extension, Mapping):
                continue
            oid = str(extension.get("oid") or "")
            if oid == "2.5.29.14":
                value = extension.get("value")
                if isinstance(value, Mapping):
                    for key in ("Subject Key Identifier", "subjectKeyIdentifier", "value"):
                        digest = value.get(key)
                        if isinstance(digest, str) and digest.strip():
                            return format_hex_string_lines(digest)
                raw_bytes = extension.get("bytes")
                if isinstance(raw_bytes, (bytes, bytearray)):
                    return format_hex_bytes_lines(bytes(raw_bytes))

    if isinstance(decoded, Mapping):
        der_b64 = decoded.get("derBase64")
        if isinstance(der_b64, str) and der_b64.strip():
            try:
                der_bytes = base64.b64decode(der_b64, validate=True)
            except (ValueError, binascii.Error):
                der_bytes = None
            if der_bytes:
                try:
                    certificate = x509.load_der_x509_certificate(der_bytes)
                except Exception:
                    certificate = None
                if certificate is not None:
                    try:
                        ski_extension = certificate.extensions.get_extension_for_oid(
                            ExtensionOID.SUBJECT_KEY_IDENTIFIER
                        )
                    except x509.ExtensionNotFound:
                        try:
                            derived = x509.SubjectKeyIdentifier.from_public_key(
                                certificate.public_key()
                            )
                        except Exception:
                            digest_bytes = None
                        else:
                            digest_bytes = derived.digest
                    else:
                        digest_bytes = ski_extension.value.digest
                    if digest_bytes:
                        return format_hex_bytes_lines(digest_bytes)

    public_key_info = decoded.get("publicKeyInfo") if isinstance(decoded, Mapping) else None
    if isinstance(public_key_info, Mapping):
        spki_b64 = public_key_info.get("subjectPublicKeyInfoBase64")
        if isinstance(spki_b64, str) and spki_b64.strip():
            cleaned = re.sub(r"\s+", "", spki_b64)
            try:
                spki_bytes = base64.b64decode(cleaned, validate=True)
            except (ValueError, binascii.Error):
                pass
            else:
                digest = hashlib.sha1(spki_bytes).digest()
                return format_hex_bytes_lines(digest)

    return []


def _append_simple_field(lines: List[str], label: str, value: Optional[Any], default: str = "(none)") -> None:
    if value is None:
        lines.append(f"{label}:\t{default}")
    else:
        lines.append(f"{label}:\t{value}")


def _append_multiline_field(
    lines: List[str],
    label: str,
    content_lines: Iterable[str],
    *,
    indent_str: str = "",
    default: str = "(none)",
    force_multiline: bool = False,
) -> None:
    filtered = [line for line in content_lines if line is not None]
    if not filtered:
        lines.append(f"{label}:\t{default}")
        return
    if len(filtered) == 1 and not force_multiline:
        lines.append(f"{label}:\t{filtered[0]}")
        return
    lines.append(f"{label}:\t")
    prefix = indent_str
    for line in filtered:
        lines.append(f"{prefix}{line}")


def _format_json_block(value: Any) -> List[str]:
    if value is None:
        return []
    try:
        return json.dumps(value, indent=2, sort_keys=False).splitlines()
    except (TypeError, ValueError):
        return [str(value)]


def _format_boolean(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and value in (0, 1):
        return "true" if bool(value) else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered
    return None


def _format_counter_value(counter: Any) -> Optional[str]:
    try:
        count = int(counter)
    except (TypeError, ValueError):
        return None
    if count < 0:
        return str(count)
    return f"0x{count:08x}={count}"


def _format_flag_line(flags: Any) -> Optional[str]:
    if not isinstance(flags, Mapping):
        return None
    try:
        value = int(flags.get("value"))
    except (TypeError, ValueError):
        return None
    bitfield = flags.get("bitfield")
    if not isinstance(bitfield, str) or not bitfield.startswith("0b"):
        bitfield = f"0b{value:08b}"
    components = [
        f"UP:{1 if flags.get('userPresent') else 0}",
        f"UV:{1 if flags.get('userVerified') else 0}",
        f"BE:{1 if flags.get('backupEligibility') else 0}",
        f"BS:{1 if flags.get('backupState') else 0}",
        f"AT:{1 if flags.get('attestedCredentialDataIncluded') else 0}",
        f"ED:{1 if flags.get('extensionDataIncluded') else 0}",
    ]
    return f"0x{value:02x}={bitfield}= {' '.join(components)}"


def _build_authenticator_data_lines(
    auth_bytes: Optional[bytes], auth_details: Optional[Mapping[str, Any]]
) -> List[str]:
    if auth_bytes:
        rp = auth_bytes[:32].hex()
        lines = [rp]
        if len(auth_bytes) > 32:
            lines.append(auth_bytes[32:33].hex())
        if len(auth_bytes) > 33:
            lines.append(auth_bytes[33:37].hex())
        if len(auth_bytes) > 37:
            remainder = auth_bytes[37:].hex()
            if remainder:
                lines.append(remainder)
        return lines

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
            if isinstance(rp_hex, str) and rp_hex:
                return [rp_hex]

    return []


def _parse_attested_data(auth_bytes: Optional[bytes]) -> Optional[Dict[str, bytes]]:
    if not auth_bytes or len(auth_bytes) <= 37:
        return None
    remainder = auth_bytes[37:]
    if len(remainder) < 18:
        return {"raw": remainder}
    aaguid = remainder[:16]
    length_bytes = remainder[16:18]
    credential_length = int.from_bytes(length_bytes, "big")
    credential_section = remainder[18:]
    if len(credential_section) < credential_length:
        credential_id = credential_section
        public_key = b""
    else:
        credential_id = credential_section[:credential_length]
        public_key = credential_section[credential_length:]
    return {
        "aaguid": aaguid,
        "length_bytes": length_bytes,
        "credential_id": credential_id,
        "public_key": public_key,
    }


def _collect_attested_info(
    attested: Mapping[str, Any], auth_bytes: Optional[bytes], fallback_alg: Optional[Any] = None
) -> Dict[str, Any]:
    parsed = _parse_attested_data(auth_bytes)
    credential_lines: List[str] = []
    credential_id_hex: Optional[str] = None
    aaguid_lines: List[str] = []

    if parsed and "aaguid" in parsed and isinstance(parsed["aaguid"], bytes):
        credential_lines.append(parsed["aaguid"].hex())
        aaguid_hex = parsed["aaguid"].hex()
    else:
        aaguid_hex = attested.get("aaguidHex") if isinstance(attested, Mapping) else None
        if isinstance(aaguid_hex, str):
            credential_lines.append(aaguid_hex)

    aaguid_display = attested.get("aaguid") if isinstance(attested, Mapping) else None
    if isinstance(aaguid_display, str) and aaguid_display:
        aaguid_lines.extend(filter(None, [aaguid_hex, aaguid_display]))
    elif aaguid_hex:
        aaguid_lines.append(aaguid_hex)

    if parsed and "length_bytes" in parsed and isinstance(parsed["length_bytes"], bytes):
        credential_lines.append(parsed["length_bytes"].hex())
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            length = credential.get("length")
            if isinstance(length, int):
                credential_lines.append(length.to_bytes(2, "big").hex())

    if parsed and "credential_id" in parsed and isinstance(parsed["credential_id"], bytes):
        credential_id_hex = parsed["credential_id"].hex()
        credential_lines.append(credential_id_hex)
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            credential_id_hex = credential.get("hex")
            if isinstance(credential_id_hex, str):
                credential_lines.append(credential_id_hex)

    if parsed and "public_key" in parsed and isinstance(parsed["public_key"], bytes):
        public_key_bytes = parsed["public_key"]
        if public_key_bytes:
            credential_lines.append(public_key_bytes.hex())
    else:
        public_key_bytes = b""

    public_key = attested.get("publicKey") if isinstance(attested, Mapping) else None
    algorithm_label = _resolve_cose_algorithm(public_key, fallback_alg)
    public_key_lines = _format_json_block(_convert_cose_key_for_display(public_key))

    info = {
        "credential_lines": credential_lines,
        "aaguid_lines": aaguid_lines or ([aaguid_hex] if aaguid_hex else []),
        "credential_id": credential_id_hex,
        "algorithm": algorithm_label,
        "public_key_lines": public_key_lines,
    }

    has_content = any(
        bool(info.get(key)) for key in ("credential_lines", "aaguid_lines", "credential_id", "public_key_lines")
    )
    return info if has_content else {}


_COSE_ALG_LABELS: Dict[int, str] = {
    -8: "EdDSA",
    -7: "ES256",
    -35: "ES256K",
    -36: "ES384",
    -37: "ES512",
    -257: "RS256",
    -258: "RS384",
    -259: "RS512",
}


def _resolve_cose_algorithm(public_key: Any, fallback: Optional[Any] = None) -> Optional[str]:
    alg_value: Optional[Any] = None
    if isinstance(public_key, Mapping):
        if 3 in public_key:
            alg_value = public_key[3]
        elif "3" in public_key:
            alg_value = public_key["3"]
        elif "alg" in public_key:
            alg_value = public_key["alg"]

    if alg_value is None:
        if isinstance(fallback, Mapping):
            alg_value = fallback.get("publicKeyAlgorithm")
        elif isinstance(fallback, int):
            alg_value = fallback

    if alg_value is None:
        return None

    try:
        alg_int = int(alg_value)
    except (TypeError, ValueError):
        return str(alg_value)
    return _COSE_ALG_LABELS.get(alg_int, str(alg_int))


def _convert_cose_key_for_display(public_key: Any) -> Any:
    if isinstance(public_key, Mapping):
        return {key: _convert_cose_key_for_display(value) for key, value in public_key.items()}
    if isinstance(public_key, list):
        return [_convert_cose_key_for_display(item) for item in public_key]
    if isinstance(public_key, str):
        decoded = _decode_base64_field(public_key)
        if decoded is not None:
            return decoded.hex()
    return public_key


def _decode_base64_field(value: str) -> Optional[bytes]:
    cleaned = value.strip()
    if not cleaned:
        return None
    normalized = cleaned.replace('-', '+').replace('_', '/')
    padding = (-len(normalized)) % 4
    try:
        decoded = base64.b64decode(normalized + '=' * padding)
    except (ValueError, binascii.Error):
        return None

    if base64.urlsafe_b64encode(decoded).rstrip(b'=') == cleaned.encode('ascii').rstrip(b'='):
        return decoded
    if base64.b64encode(decoded).rstrip(b'=') == normalized.encode('ascii').rstrip(b'='):
        return decoded
    return None


def _extract_hex_from_binary(entry: Any) -> Optional[str]:
    if not isinstance(entry, Mapping):
        return None
    direct_hex = entry.get("hex")
    if isinstance(direct_hex, str) and direct_hex:
        return direct_hex
    binary = entry.get("binary")
    if isinstance(binary, Mapping):
        hex_value = binary.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def _extract_bytes_from_binary(entry: Any) -> Optional[bytes]:
    if not isinstance(entry, Mapping):
        return None
    hex_value = _extract_hex_from_binary(entry)
    if isinstance(hex_value, str):
        cleaned = "".join(hex_value.split())
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        cleaned = "".join(raw_value.split())
        padding = (-len(cleaned)) % 4
        try:
            return base64.urlsafe_b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            return None

    return None


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> Optional[bytes]:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = _extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return _extract_authenticator_bytes_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> Optional[bytes]:
    attestation_bytes = _extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            cleaned = "".join(raw_value.split())
            padding = (-len(cleaned)) % 4
            try:
                attestation_bytes = base64.b64decode(cleaned + "=" * padding)
            except (ValueError, binascii.Error):
                attestation_bytes = None

    if attestation_bytes is None:
        return None

    try:
        attestation = AttestationObject(attestation_bytes)
    except Exception:  # pragma: no cover - defensive against malformed input
        return None

    try:
        return bytes(attestation.auth_data)
    except Exception:  # pragma: no cover - defensive
        return None


def _extend_with_authenticator_details(
    lines: List[str],
    auth_details: Optional[Mapping[str, Any]],
    auth_bytes: Optional[bytes],
    response_context: Optional[Mapping[str, Any]] = None,
) -> None:
    data_lines = _build_authenticator_data_lines(auth_bytes, auth_details)
    _append_multiline_field(lines, "Authenticator data", data_lines)

    rp_hex = None
    flags_info = None
    sign_count = None
    attested_info: Optional[Dict[str, Any]] = None

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
        flags_info = auth_details.get("flags")
        sign_count = auth_details.get("signCount")
        attested = auth_details.get("attestedCredentialData")
        if isinstance(attested, Mapping):
            fallback_alg = None
            if isinstance(response_context, Mapping):
                fallback_alg = response_context.get("publicKeyAlgorithm")
            attested_info = _collect_attested_info(attested, auth_bytes, fallback_alg)

    _append_simple_field(lines, "RP ID hash", rp_hex)
    flag_line = _format_flag_line(flags_info)
    _append_multiline_field(
        lines,
        "Flags",
        [flag_line] if flag_line else [],
        force_multiline=True,
    )
    _append_simple_field(lines, "Counter", _format_counter_value(sign_count))

    if attested_info:
        _append_multiline_field(lines, "Credential data", attested_info.get("credential_lines", []))
        _append_multiline_field(lines, "AAGUID", attested_info.get("aaguid_lines", []))
        _append_simple_field(lines, "Credential ID", attested_info.get("credential_id"))
        _append_simple_field(lines, "Key algorithm", attested_info.get("algorithm"))
        _append_multiline_field(
            lines,
            "Public key",
            attested_info.get("public_key_lines", []),
            indent_str="  ",
        )


def _extend_with_authenticator_extensions(lines: List[str], auth_details: Any) -> None:
    if not isinstance(auth_details, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    extensions = auth_details.get("extensions")
    if not isinstance(extensions, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    summary = extensions.get("summary")
    raw_value = extensions.get("raw")
    content = summary if summary is not None else raw_value
    if content is None:
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    _append_multiline_field(lines, "Authenticator extensions", _format_json_block(content), indent_str="  ")


def _extend_with_client_extensions(lines: List[str], extensions: Any) -> None:
    if extensions is None:
        _append_simple_field(lines, "Client extensions", None)
        return
    _append_multiline_field(lines, "Client extensions", _format_json_block(extensions), indent_str="  ")


def _extend_with_attestation_section(
    lines: List[str],
    attestation_entry: Any,
    attestation_details: Any,
    *,
    include_certificates: bool = True,
) -> None:
    att_hex = _extract_hex_from_binary(attestation_entry)
    _append_simple_field(lines, "Attestation object", att_hex)

    att_format = None
    certificates = None
    if isinstance(attestation_details, Mapping):
        att_format = attestation_details.get("attestationFormat")
        certificates = attestation_details.get("attestationCertificate")

    _append_simple_field(lines, "Att. format", att_format)

    if not include_certificates:
        lines.append("Att. certificates:\t")
        return

    if isinstance(certificates, Mapping):
        summary = certificates.get("summary")
        if isinstance(summary, str) and summary.strip():
            cert_lines = summary.splitlines()
        else:
            cert_lines = _format_json_block(certificates)
        _append_multiline_field(lines, "Att. certificates", cert_lines, indent_str="  ")
    else:
        _append_simple_field(lines, "Att. certificates", None)


def _extend_with_client_data_entry(lines: List[str], client_data_entry: Any) -> None:
    details = None
    if isinstance(client_data_entry, Mapping):
        details = client_data_entry.get("details")
    _extend_with_client_data_details(lines, details)


def _extend_with_client_data_details(lines: List[str], details: Any) -> None:
    if not isinstance(details, Mapping):
        _append_simple_field(lines, "Client data", None)
        _append_simple_field(lines, "Type", None)
        _append_simple_field(lines, "Challenge", None)
        _append_simple_field(lines, "Origin", None)
        _append_simple_field(lines, "Cross-origin", None)
        return

    raw_json = details.get("rawJson")
    client_data_lines: List[str]
    if isinstance(raw_json, Mapping):
        client_data_lines = _format_json_block(raw_json)
    else:
        raw_text = details.get("rawText")
        if isinstance(raw_text, str) and raw_text.strip():
            client_data_lines = raw_text.splitlines()
        else:
            filtered = {
                key: details.get(key)
                for key in ("type", "challenge", "origin", "crossOrigin")
                if key in details
            }
            client_data_lines = _format_json_block(filtered)

    _append_multiline_field(lines, "Client data", client_data_lines, indent_str="  ")

    type_value = details.get("type")
    challenge = details.get("challenge")
    if isinstance(challenge, Mapping):
        challenge_value = challenge.get("hex") or challenge.get("raw")
    else:
        challenge_value = challenge
    origin = details.get("origin")
    cross_origin_value = details.get("crossOrigin")
    cross_origin_text = _format_boolean(cross_origin_value)
    if cross_origin_text is None and cross_origin_value is not None:
        cross_origin_text = str(cross_origin_value)

    _append_simple_field(lines, "Type", type_value)
    _append_simple_field(lines, "Challenge", challenge_value)
    _append_simple_field(lines, "Origin", origin)
    _append_simple_field(lines, "Cross-origin", cross_origin_text)
