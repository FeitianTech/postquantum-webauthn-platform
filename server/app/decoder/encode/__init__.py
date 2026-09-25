"""Encoding helpers for the codec pipeline.

The implementation lives in this package's submodules; this module is the public
face of it and re-exports the pieces callers and tests reach for.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from cbor2 import (  # noqa: F401  # re-exported for callers and tests
    CBORSimpleValue,
    CBORTag,
    undefined,
)

# Many imported names are intentionally re-exported for callers and tests that
# reach encoder internals directly via `server.app.decoder.encode`.
from ..decode.json_input import read as read_json
from .binary_decode import (
    _maybe_decode_bytes,  # noqa: F401  # re-exported for callers and tests
    _require_bytes,  # noqa: F401  # re-exported for callers and tests
    _require_certificate_bytes,  # noqa: F401  # re-exported for callers and tests
)
from .binary_extract import (
    _determine_pem_label,  # noqa: F401  # re-exported for callers and tests
    _extract_binary_input,  # noqa: F401  # re-exported for callers and tests
    _extract_generic_binary_payload,  # noqa: F401  # re-exported for callers and tests
    _normalize_pem_label,  # noqa: F401  # re-exported for callers and tests
)
from .cbor_canonical import (
    _CanonicalCBOREncoder,  # noqa: F401  # re-exported for callers and tests
    _encode_canonical_float,  # noqa: F401  # re-exported for callers and tests
    _encode_major_type_with_length,  # noqa: F401  # re-exported for callers and tests
    _encode_unsigned_integer,  # noqa: F401  # re-exported for callers and tests
)
from .ctap_encode import (
    _determine_ctap_prefix,  # noqa: F401  # re-exported for callers and tests
    _encode_ctap_from_decoded,  # noqa: F401  # re-exported for callers and tests
    _encode_ctap_from_structure,  # noqa: F401  # re-exported for callers and tests
    _encode_get_assertion_request,  # noqa: F401  # re-exported for callers and tests
    _encode_get_assertion_response,  # noqa: F401  # re-exported for callers and tests
    _encode_make_credential_request,  # noqa: F401  # re-exported for callers and tests
    _encode_make_credential_response,  # noqa: F401  # re-exported for callers and tests
)
from .ctap_fields import (
    _ctap_key_matches,  # noqa: F401  # re-exported for callers and tests
    _encode_allow_list,  # noqa: F401  # re-exported for callers and tests
    _encode_attestation_statement,  # noqa: F401  # re-exported for callers and tests
    _encode_credential_descriptor,  # noqa: F401  # re-exported for callers and tests
    _encode_ctap_user,  # noqa: F401  # re-exported for callers and tests
    _ensure_bool,  # noqa: F401  # re-exported for callers and tests
    _ensure_int,  # noqa: F401  # re-exported for callers and tests
    _ensure_text,  # noqa: F401  # re-exported for callers and tests
    _get_ctap_field_value,  # noqa: F401  # re-exported for callers and tests
    _require_mapping,  # noqa: F401  # re-exported for callers and tests
)
from .ctap_numeric import (
    _classify_ctap_numeric_mapping,  # noqa: F401  # re-exported for callers and tests
    _coerce_ctap_numeric_key,  # noqa: F401  # re-exported for callers and tests
    _extract_ctap_numeric_payload,  # noqa: F401  # re-exported for callers and tests
    _normalize_ctap_extra_value,  # noqa: F401  # re-exported for callers and tests
    _sanitize_ctap_numeric_mapping,  # noqa: F401  # re-exported for callers and tests
    _sanitize_nested_extra_key,  # noqa: F401  # re-exported for callers and tests
)
from .handlers_basic import (
    _encode_attestation_object,
    _encode_authenticator_data,
    _encode_base64_value,  # noqa: F401  # re-exported for callers and tests
    _encode_base64url_value,  # noqa: F401  # re-exported for callers and tests
    _encode_binary_value,  # noqa: F401  # re-exported for callers and tests
    _encode_client_data,
    _encode_der_value,
    _encode_hex_value,  # noqa: F401  # re-exported for callers and tests
    _encode_json_value,
    _encode_pem_value,
    _encode_public_key_credential,
    _encode_x509_certificate,
    _normalize_encoding_format,
    _prepare_encoder_response,  # noqa: F401  # re-exported for callers and tests
)
from .handlers_cbor import (
    _encode_cbor_value,
    _encode_cose_value,
    _encode_ctap_webauthn_value,
)
from .handlers_edn import _encode_edn_value

__all__ = ["encode_payload_text"]


def encode_payload_text(value: str, target_format: str) -> dict[str, Any]:
    """Encode ``value`` into the requested ``target_format``."""

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Encoder input is empty.")

    canonical = _normalize_encoding_format(target_format)
    if canonical == "edn":
        # EDN is not JSON: its text is the item, read by decoder/edn -- as sent,
        # so that the offset a refusal names counts the text's leading blank space.
        return _encode_edn_value(value)

    try:
        parsed, repeated = read_json(trimmed)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive guard
        raise ValueError(
            "Encoder expects a JSON document describing the value to encode."
        ) from exc
    if repeated:
        # json.loads would keep one of the values: refuse rather than drop one.
        first = repeated[0]
        raise ValueError(
            f"The JSON repeats the key {json.dumps(first['key'], ensure_ascii=False)} at {first['path']}, "
            "and encoding it would drop a value. Remove one, or write the item in EDN (format \"EDN\"), "
            "which can repeat a key."
        )

    handler = _ENCODING_HANDLERS.get(canonical)
    if handler is None:
        raise ValueError(f"Unsupported encoder format: {target_format}")

    return handler(parsed)


_ENCODING_HANDLERS: dict[str, Callable[[Any], dict[str, Any]]] = {
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
