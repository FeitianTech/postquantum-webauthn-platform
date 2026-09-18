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
import sys
import types
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

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
from .decode_parts import (
    binary_extract,
    cbor_core,
    cbor_lenient,
    cbor_runtime,
    cbor_sequence,
    cbor_strict,
    certificate_extensions,
    certificate_summary,
    conversion_cert_leaf,
    conversion_leaf,
    ctap_classify,
    ctap_convert_leaf,
    ctap_repair_leaf,
    ctap_repair_make,
    ctap_runtime_interpret,
    ctap_runtime_parse,
    details_runtime,
    key_utils,
    pipeline_runtime,
    result_runtime,
    summary_leaf,
    summary_runtime,
)
from .decode_parts.binary_extract import (
    _convert_cose_key_for_display,
    _decode_base64_field,
    _extract_bytes_from_binary,
    _extract_hex_from_binary,
    _resolve_cose_algorithm,
)
from .decode_parts.cbor_sequence import _decode_cbor_sequence_impl
from .decode_parts.certificate_extensions import (
    _DEVICE_IDENTIFIER_NAMES,
    _build_certificate_extensions_lines,
    _format_certificate_extension_header,
    _format_certificate_extension_value,
    _format_device_identifier_line,
)
from .decode_parts.certificate_summary import (
    _build_certificate_summary_lines as _build_certificate_summary_lines_impl,
)
from .decode_parts.certificate_summary import (
    _build_fingerprint_lines,
    _build_signature_lines,
    _build_subject_key_identifier_lines,
    _build_subject_public_key_info_lines,
    _format_certificate_time,
    _format_public_key_point_lines,
)
from .decode_parts.conversion_cert_leaf import (
    _convert_attestation_entry_impl,
    _convert_attestation_statement_impl,
    _convert_certificate_bytes_impl,
    _convert_certificate_chain_impl,
    _convert_certificate_payload_impl,
)
from .decode_parts.conversion_leaf import (
    _build_authenticator_data_payload,
    _build_credential_overview,
    _build_credential_payload,
    _build_flag_payload,
    _collect_response_extras,
    _convert_client_data_entry,
)
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
from .decode_parts.ctap_convert_leaf import (
    _attempt_decode_cbor_map,
    _convert_ctap_credential_descriptor,
    _convert_optional_ctap_field,
    _normalize_user_mapping,
)
from .decode_parts.key_utils import (
    MISSING as _MISSING,
)
from .decode_parts.key_utils import (
    coerce_cbor_bytes as _coerce_cbor_bytes,
)
from .decode_parts.key_utils import (
    generate_key_variants as _generate_key_variants,
)
from .decode_parts.key_utils import (
    get_mapping_entry as _get_mapping_entry,
)
from .decode_parts.key_utils import (
    hex_json_safe as _hex_json_safe,
)
from .decode_parts.key_utils import (
    int_to_key_bytes as _int_to_key_bytes,
)
from .decode_parts.key_utils import (
    key_variant_identity as _key_variant_identity,
)
from .decode_parts.key_utils import (
    make_hex_only as _make_hex_only,
)
from .decode_parts.key_utils import (
    stringify_mapping_keys as _stringify_mapping_keys,
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


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> bytes | None:
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


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> bytes | None:
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

_CTAP_COMMAND_MAP = cbor_runtime._CTAP_COMMAND_MAP
_CTAP_STATUS_MAP = cbor_runtime._CTAP_STATUS_MAP
_extract_ctap_prefix = cbor_runtime._extract_ctap_prefix
_is_padding_bytes = cbor_runtime._is_padding_bytes


# Compatibility shims for tests and callers that monkeypatch decoder-local helpers.
_CborDecodingError = cbor_core._CborDecodingError
_ensure_cbor_available = cbor_core._ensure_cbor_available
_float_summary = cbor_core._float_summary
_read_cbor_length = cbor_core._read_cbor_length
_lenient_read_uint = cbor_core._lenient_read_uint
_lenient_decode_from = cbor_core._lenient_decode_from
_structure_to_value = cbor_core._structure_to_value


def _parse_cbor_item(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    original_read_cbor_length = cbor_core._read_cbor_length
    original_ensure_cbor_available = cbor_core._ensure_cbor_available
    original_float_summary = cbor_core._float_summary
    try:
        cbor_core._read_cbor_length = _read_cbor_length
        cbor_core._ensure_cbor_available = _ensure_cbor_available
        cbor_core._float_summary = _float_summary
        return cbor_core._parse_cbor_item(data, offset)
    finally:
        cbor_core._read_cbor_length = original_read_cbor_length
        cbor_core._ensure_cbor_available = original_ensure_cbor_available
        cbor_core._float_summary = original_float_summary


def _decode_cbor_structure(data: bytes) -> tuple[dict[str, Any], int]:
    node, offset = _parse_cbor_item(data, 0)
    node.setdefault("byteLength", offset)
    return node, offset


_derive_alg_from_auth_data = ctap_repair_leaf._derive_alg_from_auth_data
_extract_mapping_bytes = ctap_repair_leaf._extract_mapping_bytes
_extract_mapping_string = ctap_repair_leaf._extract_mapping_string
_locate_get_assertion_trailing_offset = ctap_repair_leaf._locate_get_assertion_trailing_offset
_merge_ctap_make_credential = ctap_repair_leaf._merge_ctap_make_credential
_merge_trailing_signature = ctap_repair_leaf._merge_trailing_signature
_repair_make_credential_entries = ctap_repair_leaf._repair_make_credential_entries
_split_get_assertion_trailing_fields = ctap_repair_leaf._split_get_assertion_trailing_fields


def _extract_get_assertion_trailing_from_raw(
    raw_bytes: bytes,
) -> tuple[bytes | None, dict[int, Any]]:
    original_locate_trailing_offset = ctap_repair_leaf._locate_get_assertion_trailing_offset
    original_lenient_decode = ctap_repair_leaf._lenient_decode_from
    try:
        ctap_repair_leaf._locate_get_assertion_trailing_offset = _locate_get_assertion_trailing_offset
        ctap_repair_leaf._lenient_decode_from = _lenient_decode_from
        return ctap_repair_leaf._extract_get_assertion_trailing_from_raw(raw_bytes)
    finally:
        ctap_repair_leaf._locate_get_assertion_trailing_offset = original_locate_trailing_offset
        ctap_repair_leaf._lenient_decode_from = original_lenient_decode



_json_safe_with_stringified_keys = cbor_runtime._json_safe_with_stringified_keys


def _run_with_decode_globals(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    rebound = _RUNTIME_REBOUND_CACHE.get(func)
    if rebound is None:
        rebound = types.FunctionType(
            func.__code__,
            globals(),
            name=func.__name__,
            argdefs=func.__defaults__,
            closure=func.__closure__,
        )
        _RUNTIME_REBOUND_CACHE[func] = rebound
    return rebound(*args, **kwargs)


def _bind_runtime_function(func: Callable[..., Any]) -> Callable[..., Any]:
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        return _run_with_decode_globals(func, *args, **kwargs)

    return _wrapped


def _install_runtime_bindings(bindings: Mapping[str, Callable[..., Any]]) -> None:
    for _name, _func in bindings.items():
        globals()[_name] = _bind_runtime_function(_func)


_RUNTIME_REBOUND_CACHE: dict[Callable[..., Any], Callable[..., Any]] = {}

_PEM_CERT_PATTERN = pipeline_runtime._PEM_CERT_PATTERN


decode_payload_text = pipeline_runtime.decode_payload_text


_PIPELINE_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_decode_json_object": pipeline_runtime._decode_json_object,
    "_decode_public_key_credential": pipeline_runtime._decode_public_key_credential,
    "_decode_pem_certificates": pipeline_runtime._decode_pem_certificates,
    "_decode_binary_payload": pipeline_runtime._decode_binary_payload,
    "_decode_binary_input": pipeline_runtime._decode_binary_input,
    "_decode_binary_field": pipeline_runtime._decode_binary_field,
    "_try_parse_json": pipeline_runtime._try_parse_json,
    "_looks_like_pem": pipeline_runtime._looks_like_pem,
    "_try_decode_certificate_bytes": pipeline_runtime._try_decode_certificate_bytes,
    "_try_decode_attestation_object": pipeline_runtime._try_decode_attestation_object,
    "_try_decode_authenticator_data": pipeline_runtime._try_decode_authenticator_data,
    "_expand_cbor_value": pipeline_runtime._expand_cbor_value,
}

_CBOR_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_decode_cbor_sequence": cbor_runtime._decode_cbor_sequence,
    "_repair_get_assertion_entries": cbor_runtime._repair_get_assertion_entries,
    "_try_decode_cbor": cbor_runtime._try_decode_cbor,
}

_CTAP_PARSE_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_convert_ctap_allow_list": ctap_runtime_parse._convert_ctap_allow_list,
    "_convert_pub_key_cred_params": ctap_runtime_parse._convert_pub_key_cred_params,
    "_convert_auth_data_field": ctap_runtime_parse._convert_auth_data_field,
    "_convert_signature_field": ctap_runtime_parse._convert_signature_field,
    "_convert_att_stmt_field": ctap_runtime_parse._convert_att_stmt_field,
    "_convert_ctap_user_field": ctap_runtime_parse._convert_ctap_user_field,
    "_summarize_bytes_for_json": ctap_runtime_parse._summarize_bytes_for_json,
    "_parse_authenticator_data_bytes": ctap_runtime_parse._parse_authenticator_data_bytes,
    "_format_auth_data_for_expanded_json": ctap_runtime_parse._format_auth_data_for_expanded_json,
    "_format_att_stmt_for_expanded_json": ctap_runtime_parse._format_att_stmt_for_expanded_json,
    "_decode_trailing_map": ctap_runtime_parse._decode_trailing_map,
    "_extract_lenient_map_entries": ctap_runtime_parse._extract_lenient_map_entries,
    "_extract_signature_from_raw_bytes": ctap_runtime_parse._extract_signature_from_raw_bytes,
    "_convert_user_text_value": ctap_runtime_parse._convert_user_text_value,
    "_convert_ctap_user": ctap_runtime_parse._convert_ctap_user,
}

_CTAP_INTERPRET_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_build_make_credential_request_expanded_json": ctap_runtime_interpret._build_make_credential_request_expanded_json,
    "_build_get_assertion_request_expanded_json": ctap_runtime_interpret._build_get_assertion_request_expanded_json,
    "_build_make_credential_expanded_json": ctap_runtime_interpret._build_make_credential_expanded_json,
    "_build_get_assertion_expanded_json": ctap_runtime_interpret._build_get_assertion_expanded_json,
    "_interpret_ctap_cbor_value": ctap_runtime_interpret._interpret_ctap_cbor_value,
    "_interpret_make_credential_map": ctap_runtime_interpret._interpret_make_credential_map,
    "_interpret_get_assertion_map": ctap_runtime_interpret._interpret_get_assertion_map,
    "_interpret_make_credential_request_map": ctap_runtime_interpret._interpret_make_credential_request_map,
    "_interpret_get_assertion_request_map": ctap_runtime_interpret._interpret_get_assertion_request_map,
}

_install_runtime_bindings(
    {
        **_PIPELINE_RUNTIME_BINDINGS,
        **_CBOR_RUNTIME_BINDINGS,
        **_CTAP_PARSE_RUNTIME_BINDINGS,
        **_CTAP_INTERPRET_RUNTIME_BINDINGS,
    }
)


_MAKE_CREDENTIAL_REQUEST_HANDLERS = ctap_runtime_interpret._MAKE_CREDENTIAL_REQUEST_HANDLERS
_GET_ASSERTION_REQUEST_HANDLERS = ctap_runtime_interpret._GET_ASSERTION_REQUEST_HANDLERS
_MAKE_CREDENTIAL_RESPONSE_HANDLERS = ctap_runtime_interpret._MAKE_CREDENTIAL_RESPONSE_HANDLERS
_GET_ASSERTION_RESPONSE_HANDLERS = ctap_runtime_interpret._GET_ASSERTION_RESPONSE_HANDLERS

_DETAILS_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_describe_client_data_from_bytes": details_runtime._describe_client_data_from_bytes,
    "_describe_authenticator_data_bytes": details_runtime._describe_authenticator_data_bytes,
    "_parse_attestation_object": details_runtime._parse_attestation_object,
    "_extract_attestation_certificate": details_runtime._extract_attestation_certificate,
    "_build_client_data_details": details_runtime._build_client_data_details,
    "_binary_summary": details_runtime._binary_summary,
    "_try_decode_utf8": details_runtime._try_decode_utf8,
    "_is_public_key_credential": details_runtime._is_public_key_credential,
    "_is_client_data_dict": details_runtime._is_client_data_dict,
}

_RESULT_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_prepare_decoder_response": result_runtime._prepare_decoder_response,
    "_build_decoder_payload": result_runtime._build_decoder_payload,
    "_convert_result_to_data": result_runtime._convert_result_to_data,
    "_convert_public_key_credential_data": result_runtime._convert_public_key_credential_data,
    "_convert_attestation_object_data": result_runtime._convert_attestation_object_data,
    "_convert_authenticator_data_result": result_runtime._convert_authenticator_data_result,
    "_convert_client_data_result": result_runtime._convert_client_data_result,
    "_convert_certificate_result": result_runtime._convert_certificate_result,
    "_convert_attestation_entry": result_runtime._convert_attestation_entry,
    "_convert_attestation_statement": result_runtime._convert_attestation_statement,
    "_convert_certificate_chain": result_runtime._convert_certificate_chain,
    "_convert_certificate_bytes": result_runtime._convert_certificate_bytes,
    "_convert_certificate_payload": result_runtime._convert_certificate_payload,
    "_build_authenticator_section": result_runtime._build_authenticator_section,
}

_SUMMARY_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_format_result_summary": summary_runtime._format_result_summary,
    "_base_type": summary_runtime._base_type,
    "_format_public_key_credential_summary": summary_runtime._format_public_key_credential_summary,
    "_format_attestation_object_summary": summary_runtime._format_attestation_object_summary,
    "_format_authenticator_data_summary": summary_runtime._format_authenticator_data_summary,
    "_format_client_data_summary": summary_runtime._format_client_data_summary,
    "_format_certificate_summary": summary_runtime._format_certificate_summary,
    "_format_json_summary": summary_runtime._format_json_summary,
    "_format_cbor_summary": summary_runtime._format_cbor_summary,
    "_format_generic_summary": summary_runtime._format_generic_summary,
    "_build_certificate_summary_lines": summary_runtime._build_certificate_summary_lines,
    "_extend_with_authenticator_details": summary_runtime._extend_with_authenticator_details,
    "_extend_with_authenticator_extensions": summary_runtime._extend_with_authenticator_extensions,
    "_extend_with_client_extensions": summary_runtime._extend_with_client_extensions,
    "_extend_with_attestation_section": summary_runtime._extend_with_attestation_section,
    "_extend_with_client_data_entry": summary_runtime._extend_with_client_data_entry,
    "_extend_with_client_data_details": summary_runtime._extend_with_client_data_details,
}

_install_runtime_bindings(
    {
        **_DETAILS_RUNTIME_BINDINGS,
        **_RESULT_RUNTIME_BINDINGS,
        **_SUMMARY_RUNTIME_BINDINGS,
    }
)


