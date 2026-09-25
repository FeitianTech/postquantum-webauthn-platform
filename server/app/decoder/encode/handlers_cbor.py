"""CBOR/CTAP-focused encoder handlers."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..cbor_canonical import _canonical_cbor_dumps, _canonicalize_cbor_structure
from ..decode import _binary_summary, _hex_json_safe, _stringify_mapping_keys
from . import ctap_views
from .constants import _CTAP_FIELD_LABELS, _CTAP_PREFIX_DETAILS, _CTAP_REQUIRED_FIELDS
from .cose_key import encode_cose_key
from .ctap_encode import (
    _encode_get_assertion_request,
    _encode_get_assertion_response,
    _encode_make_credential_request,
    _encode_make_credential_response,
)
from .ctap_numeric import _extract_ctap_numeric_payload, _normalize_ctap_extra_value
from .handlers_basic import _prepare_encoder_response
from .typed_keys import with_cbor_keys


def _encode_cbor_value(parsed: Any, *, base_type: str = "CBOR (canonical)") -> dict[str, Any]:
    """JSON as CTAP2-canonical CBOR; a CTAP message only from the decoder's explicit CTAP view.

    That view is ``ctapDecoded``, or ``expandedJson`` beside the ``ctap``
    framing that names its message (``ctap_views``); either must rebuild, or the
    encoder says why. Any other object is a plain map -- even one whose keys look like
    CTAP members ("1", "fmt", "signature"): the encoder does not guess.
    """

    if isinstance(parsed, Mapping):
        answer = ctap_views.encode(parsed, base_type)
        if answer is not None:
            return answer

    parsed = with_cbor_keys(parsed)
    payload_bytes = _canonical_cbor_dumps(parsed)
    payload = {
        "binary": _binary_summary(payload_bytes, "cbor"),
        "decodedValue": _stringify_mapping_keys(
            _hex_json_safe(_canonicalize_cbor_structure(parsed))
        ),
    }
    return _prepare_encoder_response(base_type, payload, qualifier="encoded")


def _encode_ctap_webauthn_value(parsed: Any) -> dict[str, Any]:
    # The decoder's view of a CTAP message is rebuilt as it is, as format CBOR rebuilds it.
    if isinstance(parsed, Mapping) and (answer := ctap_views.encode(parsed, "CBOR (CTAP/WebAuthn Data)")):
        return answer
    numeric_map, ctap_type = _extract_ctap_numeric_payload(parsed)

    field_labels = _CTAP_FIELD_LABELS.get(ctap_type, {})
    for index in _CTAP_REQUIRED_FIELDS.get(ctap_type, ()):  # pragma: no branch - small tuple
        if index not in numeric_map:
            label = field_labels.get(index, f"0x{index:02x}")
            raise ValueError(f"Missing field 0x{index:02x} ({label})")

    structure = {
        label: numeric_map[index]
        for index, label in field_labels.items()
        if index in numeric_map
    }

    encoder_map = {
        "makeCredentialRequest": _encode_make_credential_request,
        "getAssertionRequest": _encode_get_assertion_request,
        "makeCredentialResponse": _encode_make_credential_response,
        "getAssertionResponse": _encode_get_assertion_response,
    }
    encoder = encoder_map.get(ctap_type)
    if encoder is None:  # pragma: no cover - defensive guard
        raise ValueError("Unsupported CTAP/WebAuthn data type.")

    encoded_map = encoder(structure)
    decoded_structure = {
        label: encoded_map[index]
        for index, label in field_labels.items()
        if index in encoded_map
    }

    extras: dict[int, Any] = {}
    for index, value in numeric_map.items():
        if index not in field_labels:
            extras[index] = _normalize_ctap_extra_value(value)

    if extras:
        encoded_map = dict(encoded_map)
        for index, value in extras.items():
            encoded_map[index] = value
        for index, value in extras.items():
            decoded_structure[str(index)] = value

    prefix_code, prefix_kind = _CTAP_PREFIX_DETAILS.get(ctap_type, (None, None))
    payload_bytes = _canonical_cbor_dumps(encoded_map)
    full_bytes = (
        bytes([prefix_code]) + payload_bytes if isinstance(prefix_code, int) else payload_bytes
    )
    canonical_encoded_map = _canonicalize_cbor_structure(encoded_map)
    canonical_decoded_structure = _canonicalize_cbor_structure(decoded_structure)

    payload: dict[str, Any] = {
        "binary": _binary_summary(full_bytes, "cbor"),
        "encodedValue": _stringify_mapping_keys(
            _hex_json_safe(canonical_encoded_map)
        ),
        "ctapDecoded": _stringify_mapping_keys(
            _hex_json_safe({ctap_type: canonical_decoded_structure})
        ),
    }

    if isinstance(prefix_code, int):
        payload["ctap"] = {
            "code": prefix_code,
            "codeHex": f"0x{prefix_code:02x}",
            "kind": prefix_kind,
        }

    qualifier = f"encoded {ctap_type}"
    return _prepare_encoder_response(
        "CBOR (CTAP/WebAuthn Data)", payload, qualifier=qualifier
    )


def _encode_cose_value(parsed: Any) -> dict[str, Any]:
    # A COSE_Key, never a CTAP message: its labels 1 and 3 are kty and alg.
    return encode_cose_key(parsed)
