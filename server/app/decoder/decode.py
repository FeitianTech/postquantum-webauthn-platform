"""Utilities for decoding WebAuthn-related payloads for the demo decoder."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import sys
import string
import struct
import uuid
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import cbor2
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fido2 import cbor
from fido2.utils import ByteBuffer
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData

from ..attestation import (
    colon_hex,
    encode_base64url,
    format_hex_bytes_lines,
    format_hex_string_lines,
    make_json_safe,
    serialize_attestation_certificate,
    summarize_authenticator_extensions,
)
from .decode_parts.key_utils import (
    MISSING as _MISSING,
    coerce_cbor_bytes as _coerce_cbor_bytes,
    generate_key_variants as _generate_key_variants,
    get_mapping_entry as _get_mapping_entry,
    hex_json_safe as _hex_json_safe,
    int_to_key_bytes as _int_to_key_bytes,
    key_variant_identity as _key_variant_identity,
    make_hex_only as _make_hex_only,
    stringify_mapping_keys as _stringify_mapping_keys,
)
from .decode_parts.certificate_extensions import (
    _DEVICE_IDENTIFIER_NAMES,
    _build_certificate_extensions_lines,
    _format_certificate_extension_header,
    _format_certificate_extension_value,
    _format_device_identifier_line,
)
from .decode_parts.certificate_summary import (
    _build_certificate_summary_lines as _build_certificate_summary_lines_impl,
    _build_fingerprint_lines,
    _build_signature_lines,
    _build_subject_key_identifier_lines,
    _build_subject_public_key_info_lines,
    _format_certificate_time,
    _format_public_key_point_lines,
)
from .decode_parts import cbor_core as _cbor_core
from .decode_parts.cbor_sequence import _decode_cbor_sequence_impl
from .decode_parts import ctap_repair_leaf as _ctap_repair_leaf
from .decode_parts.ctap_classify import (
    _GET_ASSERTION_REQUEST_LABELS,
    _GET_ASSERTION_RESPONSE_LABELS,
    _MAKE_CREDENTIAL_REQUEST_LABELS,
    _MAKE_CREDENTIAL_RESPONSE_LABELS,
    _build_labeled_ctap_map,
    _classify_ctap_map,
    _format_ctap_entry_key,
    _looks_like_get_assertion_output,
    _looks_like_get_assertion_request,
    _looks_like_make_credential_output,
    _looks_like_make_credential_request,
    _resolve_ctap_label,
)
from .decode_parts.binary_extract import (
    _convert_cose_key_for_display,
    _decode_base64_field,
    _extract_bytes_from_binary,
    _extract_hex_from_binary,
    _resolve_cose_algorithm,
)
from .decode_parts.summary_leaf import (
    _append_multiline_field,
    _append_simple_field,
    _build_authenticator_data_lines,
    _collect_attested_info,
    _format_boolean,
    _format_counter_value,
    _format_flag_line,
    _format_json_block,
    _parse_attested_data,
)
from .decode_parts.conversion_leaf import (
    _build_authenticator_data_payload,
    _build_credential_overview,
    _build_credential_payload,
    _build_flag_payload,
    _collect_response_extras,
    _convert_client_data_entry,
)
from .decode_parts.ctap_convert_leaf import (
    _attempt_decode_cbor_map,
    _convert_ctap_credential_descriptor,
    _convert_optional_ctap_field,
    _normalize_user_mapping,
)
from .decode_parts.conversion_cert_leaf import (
    _convert_attestation_entry_impl,
    _convert_attestation_statement_impl,
    _convert_certificate_bytes_impl,
    _convert_certificate_chain_impl,
    _convert_certificate_payload_impl,
)


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> Optional[bytes]:
    module = sys.modules.get(__name__)
    extract_bytes = getattr(module, "_extract_bytes_from_binary", _extract_bytes_from_binary)
    extract_from_attestation = getattr(
        module,
        "_extract_authenticator_bytes_from_attestation",
        _extract_authenticator_bytes_from_attestation,
    )

    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = extract_bytes(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return extract_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> Optional[bytes]:
    module = sys.modules.get(__name__)
    extract_bytes = getattr(module, "_extract_bytes_from_binary", _extract_bytes_from_binary)
    attestation_class = getattr(module, "AttestationObject", AttestationObject)

    attestation_bytes = extract_bytes(attestation_entry)
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
        attestation = attestation_class(attestation_bytes)
    except Exception:
        return None

    try:
        return bytes(attestation.auth_data)
    except Exception:
        return None

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


# Compatibility shims for tests and callers that monkeypatch decoder-local helpers.
_CborDecodingError = _cbor_core._CborDecodingError
_ensure_cbor_available = _cbor_core._ensure_cbor_available
_float_summary = _cbor_core._float_summary
_read_cbor_length = _cbor_core._read_cbor_length
_lenient_read_uint = _cbor_core._lenient_read_uint
_lenient_decode_from = _cbor_core._lenient_decode_from
_structure_to_value = _cbor_core._structure_to_value


def _parse_cbor_item(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    original_read_cbor_length = _cbor_core._read_cbor_length
    original_ensure_cbor_available = _cbor_core._ensure_cbor_available
    original_float_summary = _cbor_core._float_summary
    try:
        _cbor_core._read_cbor_length = _read_cbor_length
        _cbor_core._ensure_cbor_available = _ensure_cbor_available
        _cbor_core._float_summary = _float_summary
        return _cbor_core._parse_cbor_item(data, offset)
    finally:
        _cbor_core._read_cbor_length = original_read_cbor_length
        _cbor_core._ensure_cbor_available = original_ensure_cbor_available
        _cbor_core._float_summary = original_float_summary


def _decode_cbor_structure(data: bytes) -> Tuple[Dict[str, Any], int]:
    node, offset = _parse_cbor_item(data, 0)
    node.setdefault("byteLength", offset)
    return node, offset


_derive_alg_from_auth_data = _ctap_repair_leaf._derive_alg_from_auth_data
_extract_mapping_bytes = _ctap_repair_leaf._extract_mapping_bytes
_extract_mapping_string = _ctap_repair_leaf._extract_mapping_string
_locate_get_assertion_trailing_offset = _ctap_repair_leaf._locate_get_assertion_trailing_offset
_merge_ctap_make_credential = _ctap_repair_leaf._merge_ctap_make_credential
_merge_trailing_signature = _ctap_repair_leaf._merge_trailing_signature
_repair_make_credential_entries = _ctap_repair_leaf._repair_make_credential_entries
_split_get_assertion_trailing_fields = _ctap_repair_leaf._split_get_assertion_trailing_fields


def _extract_get_assertion_trailing_from_raw(
    raw_bytes: bytes,
) -> Tuple[Optional[bytes], Dict[int, Any]]:
    original_locate_trailing_offset = _ctap_repair_leaf._locate_get_assertion_trailing_offset
    original_lenient_decode = _ctap_repair_leaf._lenient_decode_from
    try:
        _ctap_repair_leaf._locate_get_assertion_trailing_offset = _locate_get_assertion_trailing_offset
        _ctap_repair_leaf._lenient_decode_from = _lenient_decode_from
        return _ctap_repair_leaf._extract_get_assertion_trailing_from_raw(raw_bytes)
    finally:
        _ctap_repair_leaf._locate_get_assertion_trailing_offset = original_locate_trailing_offset
        _ctap_repair_leaf._lenient_decode_from = original_lenient_decode



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


def _decode_cbor_sequence(payload: bytes) -> Tuple[List[Dict[str, Any]], List[Any], int, bytes]:
    def _cbor2_decode_with_consumed(data: bytes) -> Tuple[Any, int]:
        fp = BytesIO(data)
        decoder = cbor2.CBORDecoder(fp)
        return decoder.decode(), fp.tell()

    return _decode_cbor_sequence_impl(
        payload,
        cbor_decode_from=cbor.decode_from,
        cbor_decoder_factory=_cbor2_decode_with_consumed,
        decode_cbor_structure=_decode_cbor_structure,
        structure_to_value=_structure_to_value,
        lenient_decode_from=lambda data, offset=0: _lenient_decode_from(data, offset),
        json_safe_with_stringified_keys=_json_safe_with_stringified_keys,
        cbor_error_type=_CborDecodingError,
    )


def _repair_get_assertion_entries(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    raw_bytes: Optional[bytes] = None,
) -> Tuple[Dict[str, Any], Mapping[Any, Any], Optional[bytes]]:
    if not isinstance(value, dict):
        return structure, value, None

    entries_source = structure.get("entries")
    if isinstance(entries_source, list):
        entries = entries_source
    else:
        entries = []
        structure["entries"] = entries

    signature_entry = None
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

    recovered_value = dict(value)
    recovered_fields: Dict[int, Any] = {}

    if raw_bytes:
        raw_signature, raw_field_map = _extract_get_assertion_trailing_from_raw(raw_bytes)
        if raw_signature is not None:
            signature_bytes = raw_signature
        recovered_fields.update(raw_field_map)
        if user_value is None and 4 in raw_field_map:
            user_value = raw_field_map.get(4)

    if signature_bytes is None and raw_bytes:
        for raw_key, raw_value in _extract_lenient_map_entries(raw_bytes):
            if isinstance(raw_key, int) and raw_key == 3:
                candidate_bytes = _coerce_cbor_bytes(raw_value)
                if candidate_bytes is not None:
                    signature_bytes = candidate_bytes
                    break
                if isinstance(raw_value, (bytes, bytearray)):
                    signature_bytes = bytes(raw_value)
                    break
            if isinstance(raw_key, (bytes, bytearray)):
                candidate = bytes(raw_key)
                if candidate:
                    signature_bytes = candidate
                    break

    if signature_bytes is not None:
        signature_bytes, trailing_fields = _split_get_assertion_trailing_fields(signature_bytes)
        if user_value is None and 4 in trailing_fields:
            user_value = trailing_fields.pop(4)
        for key, value in trailing_fields.items():
            recovered_fields.setdefault(key, value)

        bytes_keys = [key for key in recovered_value if isinstance(key, (bytes, bytearray))]
        for key in bytes_keys:
            recovered_value.pop(key, None)
        recovered_value[3] = signature_bytes
        sig_structure, _ = _decode_cbor_structure(cbor.encode(signature_bytes))
        entries.append(
            {
                "keySummary": "3",
                "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                "value": sig_structure,
                "valueSummary": sig_structure.get("summary"),
            }
        )

    if user_value is not None:
        recovered_value[4] = user_value
        user_structure, _ = _decode_cbor_structure(cbor.encode(user_value))
        entries.append(
            {
                "keySummary": "4",
                "key": {"majorType": 0, "type": "unsigned", "value": 4, "summary": "4"},
                "value": user_structure,
                "valueSummary": user_structure.get("summary"),
            }
        )

    for key in sorted(recovered_fields):
        if key in {3, 4}:
            continue
        if key in recovered_value:
            continue
        field_value = recovered_fields[key]
        recovered_value[key] = field_value
        field_structure, _ = _decode_cbor_structure(cbor.encode(field_value))
        entries.append(
            {
                "keySummary": str(key),
                "key": {"majorType": 0, "type": "unsigned", "value": key, "summary": str(key)},
                "value": field_structure,
                "valueSummary": field_structure.get("summary"),
            }
        )

    structure["length"] = len(entries)
    structure["summary"] = f"map[{len(entries)}]"

    return structure, recovered_value, signature_bytes


def _convert_ctap_allow_list(entry: Any) -> Any:
    if isinstance(entry, Sequence) and not isinstance(entry, (str, bytes, bytearray)):
        return [_convert_ctap_credential_descriptor(item) for item in entry]
    return _convert_optional_ctap_field(entry)


def _convert_pub_key_cred_params(entry: Any) -> Any:
    if isinstance(entry, Sequence) and not isinstance(entry, (str, bytes, bytearray)):
        return [_hex_json_safe(item) for item in entry]
    return _hex_json_safe(entry)


def _convert_auth_data_field(value: Any) -> Any:
    auth_bytes = _coerce_cbor_bytes(value)
    if auth_bytes is not None:
        auth_info, trailing = _format_auth_data_for_expanded_json(auth_bytes)
        if trailing:
            auth_info = dict(auth_info)
        return auth_info
    return _convert_optional_ctap_field(value)


def _convert_signature_field(value: Any) -> Any:
    signature_bytes = _coerce_cbor_bytes(value)
    if signature_bytes is not None:
        return signature_bytes.hex()
    if value is None:
        return None
    return _convert_optional_ctap_field(value)


def _convert_att_stmt_field(value: Any) -> Any:
    if value is None:
        return None
    return _format_att_stmt_for_expanded_json(value)


def _convert_ctap_user_field(value: Any) -> Any:
    if value is None:
        return None
    return _convert_ctap_user(value)


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


def _extract_lenient_map_entries(raw_bytes: Optional[bytes]) -> List[Tuple[Any, Any]]:
    entries: List[Tuple[Any, Any]] = []
    if not raw_bytes:
        return entries
    offset = 0
    initial = raw_bytes[offset]
    major_type = initial >> 5
    if major_type != 5:
        return entries
    info = initial & 0x1F
    offset += 1
    length, offset = _lenient_read_uint(info, raw_bytes, offset)
    for _ in range(length):
        key, new_offset = _lenient_decode_from(raw_bytes, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        value, new_offset = _lenient_decode_from(raw_bytes, offset)
        if new_offset <= offset:
            entries.append((key, None))
            break
        offset = new_offset
        entries.append((key, value))
        if offset >= len(raw_bytes):
            break
    return entries


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


def _build_make_credential_request_expanded_json(
    value: Mapping[Any, Any]
) -> Dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _build_get_assertion_request_expanded_json(
    value: Mapping[Any, Any]
) -> Dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )


def _build_make_credential_expanded_json(value: Mapping[Any, Any]) -> Dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_RESPONSE_LABELS,
        _MAKE_CREDENTIAL_RESPONSE_HANDLERS,
    )


def _build_get_assertion_expanded_json(value: Mapping[Any, Any], raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    result = _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_RESPONSE_LABELS,
        _GET_ASSERTION_RESPONSE_HANDLERS,
        missing_keys=(3,),
    )

    signature_key = _format_ctap_entry_key(3, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 3))
    auth_key = _format_ctap_entry_key(2, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 2))
    auth_details = result.get(auth_key)
    auth_trailing_bytes: Optional[bytes] = None
    if isinstance(auth_details, Mapping):
        trailing_hex = auth_details.get("trailingBytesHex")
        if isinstance(trailing_hex, str) and trailing_hex.strip():
            try:
                auth_trailing_bytes = bytes.fromhex(trailing_hex)
            except ValueError:
                auth_trailing_bytes = None

    if result.get(signature_key) is None and auth_trailing_bytes:
        trailing_map = _decode_trailing_map(auth_trailing_bytes)
        sig_entry = trailing_map.pop(3, None)
        if sig_entry is not None:
            sig_bytes = _coerce_cbor_bytes(sig_entry)
            if sig_bytes is not None:
                result[signature_key] = sig_bytes.hex()
        user_entry_trailing = trailing_map.pop(4, None)
        if user_entry_trailing is not None:
            user_key = _format_ctap_entry_key(4, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 4))
            result[user_key] = _convert_ctap_user(user_entry_trailing)
        number_entry = trailing_map.pop(5, None)
        if number_entry is not None:
            number_key = _format_ctap_entry_key(5, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 5))
            result[number_key] = _convert_optional_ctap_field(number_entry)
        user_selected_entry = trailing_map.pop(6, None)
        if user_selected_entry is not None:
            selected_key = _format_ctap_entry_key(6, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 6))
            result[selected_key] = _convert_optional_ctap_field(user_selected_entry)
        extensions_entry = trailing_map.pop(8, None)
        if extensions_entry is not None:
            extensions_key = _format_ctap_entry_key(8, _resolve_ctap_label(_GET_ASSERTION_RESPONSE_LABELS, 8))
            result[extensions_key] = _convert_optional_ctap_field(extensions_entry)
        if trailing_map:
            result["trailingFields"] = {str(k): _hex_json_safe(v) for k, v in trailing_map.items()}

    if result.get(signature_key) is None and raw_bytes:
        sig_bytes = _extract_signature_from_raw_bytes(raw_bytes)
        if sig_bytes is not None:
            result[signature_key] = sig_bytes.hex()

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
            att_stmt_candidate = _get_mapping_entry(temp_value, 3, "3", "attStmt")
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
                extra_values = []
            else:
                classification = _classify_ctap_map(working_value)
        else:
            classification = _classify_ctap_map(working_value)

        if classification == "get_assertion_output":
            base_structure, working_value, assertion_sig = _repair_get_assertion_entries(
                base_structure,
                dict(working_value),
                primary_bytes,
            )
            if assertion_sig is not None:
                merged_signature = merged_signature or assertion_sig
            extra_values = []
        elif classification == "other" and fmt_candidate is None:
            temp_structure = dict(base_structure)
            entries = base_structure.get("entries")
            if isinstance(entries, list):
                temp_structure["entries"] = [dict(entry) for entry in entries]
            temp_value = dict(working_value)
            temp_structure, temp_value, assertion_sig = _repair_get_assertion_entries(
                temp_structure,
                temp_value,
                primary_bytes,
            )
            if assertion_sig is not None:
                classification = "get_assertion_output"
                working_value = temp_value
                merged_signature = merged_signature or assertion_sig
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
            expanded_json = _build_make_credential_expanded_json(base_value)
        elif classification == "get_assertion_output":
            expanded_json = _build_get_assertion_expanded_json(base_value, primary_bytes)
        elif classification == "make_credential_input":
            expanded_json = _build_make_credential_request_expanded_json(base_value)
        elif classification == "get_assertion_input":
            expanded_json = _build_get_assertion_request_expanded_json(base_value)
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
        interpreted = _interpret_make_credential_request_map(value)
        if interpreted is not None:
            return {"makeCredentialRequest": interpreted}
        interpreted = _interpret_get_assertion_request_map(value)
        if interpreted is not None:
            return {"getAssertionRequest": interpreted}
    return None


def _interpret_make_credential_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    fmt = _get_mapping_entry(value, 1, "1", "fmt")
    fmt = fmt if fmt is not _MISSING else None
    auth_data_entry = _get_mapping_entry(value, 2, "2", "authData")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    att_stmt_entry = _get_mapping_entry(value, 3, "3", "attStmt")
    if att_stmt_entry is _MISSING:
        att_stmt_entry = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_entry)
    att_stmt_map = att_stmt_entry if isinstance(att_stmt_entry, Mapping) else None
    if not isinstance(fmt, str) or not fmt.strip() or auth_data_bytes is None:
        return None
    if att_stmt_map is None and att_stmt_bytes is None and att_stmt_entry is not None:
        return None

    interpreted: Dict[str, Any] = {}
    interpreted["1 (fmt)"] = fmt

    auth_data_details, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details
    if auth_trailing:
        trailing_map = _decode_trailing_map(auth_trailing)
        if trailing_map:
            interpreted["2 (authData trailing)"] = _hex_json_safe(trailing_map)

    if isinstance(att_stmt_map, Mapping):
        att_stmt_details = _convert_attestation_statement({"attestationStatement": att_stmt_map})
        sig_value = att_stmt_map.get("sig")
        sig_bytes = _coerce_cbor_bytes(sig_value)
        if sig_bytes is not None:
            att_stmt_details["sig"] = sig_bytes.hex()
        interpreted["3 (attStmt)"] = att_stmt_details
    else:
        if att_stmt_bytes is not None:
            interpreted["3 (attStmt)"] = att_stmt_bytes.hex()
        else:
            interpreted["3 (attStmt)"] = _hex_json_safe(att_stmt_entry)

    optional_labels = {
        4: "epAtt",
        5: "largeBlobKey",
        6: "extensions",
    }
    for key, label in optional_labels.items():
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in {1, 2, 3, 4, 5, 6}
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return interpreted


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    if _looks_like_get_assertion_request(value):
        return None
    auth_data_entry = _get_mapping_entry(value, 2, "2", "authData")
    signature_entry = _get_mapping_entry(value, 3, "3", "signature")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    signature_bytes = _coerce_cbor_bytes(signature_entry)
    if auth_data_bytes is None:
        return None

    interpreted: Dict[str, Any] = {}

    credential_entry = _get_mapping_entry(value, 1, "1", "credential")
    if credential_entry is not _MISSING and credential_entry is not None:
        interpreted["1 (credential)"] = _convert_ctap_credential_descriptor(credential_entry)

    auth_data_details, auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = _get_mapping_entry(value, 4, "4", "user")
    if user_entry is not _MISSING and user_entry is not None:
        interpreted["4 (user)"] = _convert_ctap_user(user_entry)

    optional_labels = {
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
    }
    for key, label in optional_labels.items():
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

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


def _interpret_make_credential_request_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    if not _looks_like_make_credential_request(value):
        return None
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _interpret_get_assertion_request_map(value: Mapping[Any, Any]) -> Optional[Dict[str, Any]]:
    if not _looks_like_get_assertion_request(value):
        return None
    return _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )


def _convert_user_text_value(value: Any) -> Any:
    if isinstance(value, str):
        return value

    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is None:
        return _hex_json_safe(value)

    text_value = _try_decode_utf8(data_bytes)
    binary_summary = _binary_summary(
        data_bytes, "utf-8" if text_value is not None else "binary"
    )
    if text_value is None:
        return binary_summary

    return {"text": text_value, "binary": binary_summary}


def _convert_ctap_user(entry: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        decoded_map = _attempt_decode_cbor_map(data_bytes)
        if decoded_map is not None:
            return _convert_ctap_user(decoded_map)
        return data_bytes.hex()

    if isinstance(entry, str):
        try:
            decoded_value, _ = _decode_binary_input(entry)
        except ValueError:
            decoded_value = None
        if decoded_value:
            decoded_map = _attempt_decode_cbor_map(decoded_value)
            if decoded_map is not None:
                return _convert_ctap_user(decoded_map)

    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    normalized_entry = _normalize_user_mapping(entry)

    user: Dict[str, Any] = {}
    id_value = _get_mapping_entry(normalized_entry, "id", 1)
    if id_value is not _MISSING:
        id_bytes = _coerce_cbor_bytes(id_value)
        if id_bytes is not None:
            user["id"] = id_bytes.hex()

    name_value = _get_mapping_entry(normalized_entry, "name", 2)
    if name_value is not _MISSING:
        user["name"] = _convert_user_text_value(name_value)

    display_name_value = _get_mapping_entry(normalized_entry, "displayName", 3)
    if display_name_value is not _MISSING:
        user["displayName"] = _convert_user_text_value(display_name_value)

    icon_value = _get_mapping_entry(normalized_entry, "icon", 4)
    if icon_value is not _MISSING:
        user["icon"] = _convert_user_text_value(icon_value)

    for key in normalized_entry:
        if key in {"id", "name", "displayName", "icon"} or key in {1, 2, 3, 4}:
            continue
        user[str(key)] = _hex_json_safe(normalized_entry[key])

    return user


_MAKE_CREDENTIAL_REQUEST_HANDLERS: Dict[Any, Callable[[Any], Any]] = {
    "clientDataHash": _convert_optional_ctap_field,
    "rp": _hex_json_safe,
    "user": _convert_ctap_user_field,
    "pubKeyCredParams": _convert_pub_key_cred_params,
    "excludeList": _convert_ctap_allow_list,
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
    "enterpriseAttestation": _hex_json_safe,
    "largeBlobKey": _convert_optional_ctap_field,
}

_GET_ASSERTION_REQUEST_HANDLERS: Dict[Any, Callable[[Any], Any]] = {
    "rpId": _hex_json_safe,
    "clientDataHash": _convert_optional_ctap_field,
    "allowList": _convert_ctap_allow_list,
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
    "largeBlobKey": _convert_optional_ctap_field,
}

_MAKE_CREDENTIAL_RESPONSE_HANDLERS: Dict[Any, Callable[[Any], Any]] = {
    "fmt": _hex_json_safe,
    "authData": _convert_auth_data_field,
    "attStmt": _convert_att_stmt_field,
    "epAtt": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "extensions": _convert_optional_ctap_field,
}

_GET_ASSERTION_RESPONSE_HANDLERS: Dict[Any, Callable[[Any], Any]] = {
    "credential": _convert_ctap_credential_descriptor,
    "authData": _convert_auth_data_field,
    "signature": _convert_signature_field,
    "user": _convert_ctap_user_field,
    "numberOfCredentials": _convert_optional_ctap_field,
    "userSelected": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "extensions": _convert_optional_ctap_field,
}


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
                if "makeCredentialRequest" in ctap_decoded:
                    qualifiers.append("MakeCredential request")
                if "getAssertionRequest" in ctap_decoded:
                    qualifiers.append("GetAssertion request")
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
        response, attestation_entry
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
    result.get("binary")
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


def _convert_attestation_entry(entry: Any) -> Dict[str, Any]:
    return _convert_attestation_entry_impl(
        entry,
        convert_attestation_statement=_convert_attestation_statement,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_attestation_statement(details: Any) -> Dict[str, Any]:
    payload = _convert_attestation_statement_impl(
        details,
        convert_certificate_chain=_convert_certificate_chain,
    )
    normalized: Dict[str, Any] = {}
    for key, value in payload.items():
        if key == "x5c":
            normalized[key] = value
        else:
            normalized[key] = _hex_json_safe(value)
    return normalized


def _convert_certificate_chain(value: Any) -> List[Dict[str, Any]]:
    return _convert_certificate_chain_impl(
        value,
        convert_certificate_bytes=_convert_certificate_bytes,
    )


def _convert_certificate_bytes(value: Any) -> Dict[str, Any]:
    return _convert_certificate_bytes_impl(
        value,
        serializer=serialize_attestation_certificate,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_certificate_payload(
    entry: Mapping[str, Any], cert_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    payload = _convert_certificate_payload_impl(entry, cert_bytes)
    parsed_entry = payload.get("parsedX5c")
    if parsed_entry is not None:
        payload["parsedX5c"] = _hex_json_safe(parsed_entry)
    return payload


def _build_authenticator_section(
    response: Any,
    attestation_entry: Any,
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


