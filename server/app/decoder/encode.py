"""Encoding helpers for the codec pipeline."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict

import cbor2
from cbor2 import CBORTag, CBORSimpleValue, undefined

# NOTE: This module is a compatibility facade. Many imported names are
# intentionally re-exported for callers/tests that access encoder internals
# directly via `server.app.decoder.encode`.
from .encode_parts.binary_decode import (
    _maybe_decode_bytes,
    _require_bytes,
    _require_certificate_bytes,
)
from .encode_parts.binary_extract import (
    _determine_pem_label,
    _extract_binary_input,
    _extract_generic_binary_payload,
    _format_pem_block,
    _normalize_pem_label,
    _restore_generic_structure,
)
from .encode_parts.cbor_canonical import (
    _CanonicalCBOREncoder,
    _canonical_cbor_dumps,
    _canonicalize_cbor_structure,
    _encode_canonical_float,
    _encode_major_type_with_length,
    _encode_unsigned_integer,
)
from .encode_parts.constants import (
    _CTAP_FIELD_LABELS,
    _CTAP_LABELED_KEY_PATTERN,
    _CTAP_PREFIX_DETAILS,
    _CTAP_REQUIRED_FIELDS,
)
from .encode_parts.ctap_encode import (
    _determine_ctap_prefix,
    _encode_ctap_from_decoded,
    _encode_ctap_from_structure,
    _encode_get_assertion_request,
    _encode_get_assertion_response,
    _encode_make_credential_request,
    _encode_make_credential_response,
)
from .encode_parts.ctap_fields import (
    _ctap_key_matches,
    _encode_allow_list,
    _encode_attestation_statement,
    _encode_ctap_user,
    _encode_credential_descriptor,
    _ensure_bool,
    _ensure_int,
    _ensure_text,
    _get_ctap_field_value,
    _require_mapping,
)
from .encode_parts.ctap_numeric import (
    _classify_ctap_numeric_mapping,
    _coerce_ctap_numeric_key,
    _extract_ctap_numeric_payload,
    _normalize_ctap_extra_value,
    _sanitize_ctap_numeric_mapping,
    _sanitize_nested_extra_key,
)
from .encode_parts.handlers_basic import (
    _encode_attestation_object,
    _encode_authenticator_data,
    _encode_base64_value,
    _encode_base64url_value,
    _encode_binary_value,
    _encode_client_data,
    _encode_der_value,
    _encode_hex_value,
    _encode_json_value,
    _encode_pem_value,
    _encode_public_key_credential,
    _encode_x509_certificate,
    _normalize_encoding_format,
    _prepare_encoder_response,
)
from .encode_parts.handlers_cbor import (
    _encode_cbor_value,
    _encode_cose_value,
    _encode_ctap_webauthn_value,
)

__all__ = ["encode_payload_text"]


def encode_payload_text(value: str, target_format: str) -> Dict[str, Any]:
    """Encode ``value`` into the requested ``target_format``."""

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Encoder input is empty.")

    try:
        parsed = json.loads(trimmed)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive guard
        raise ValueError(
            "Encoder expects a JSON document describing the value to encode."
        ) from exc

    canonical = _normalize_encoding_format(target_format)
    handler = _ENCODING_HANDLERS.get(canonical)
    if handler is None:
        raise ValueError(f"Unsupported encoder format: {target_format}")

    return handler(parsed)


_ENCODING_HANDLERS: Dict[str, Callable[[Any], Dict[str, Any]]] = {
    "json": _encode_json_value,
    "public-key-credential": _encode_public_key_credential,
    "client-data": _encode_client_data,
    "auth-data": _encode_authenticator_data,
    "attestation-object": _encode_attestation_object,
    "x509": _encode_x509_certificate,
    "cbor": _encode_cbor_value,
    "ctap-webauthn": _encode_ctap_webauthn_value,
    "der": _encode_der_value,
    "pem": _encode_pem_value,
    "cose": _encode_cose_value,
}
