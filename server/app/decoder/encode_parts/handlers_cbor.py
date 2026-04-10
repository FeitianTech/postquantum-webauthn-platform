"""CBOR/CTAP-focused encoder handlers."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from ..decode import _binary_summary, _hex_json_safe, _stringify_mapping_keys
from .cbor_canonical import _canonical_cbor_dumps, _canonicalize_cbor_structure
from .constants import _CTAP_FIELD_LABELS, _CTAP_PREFIX_DETAILS, _CTAP_REQUIRED_FIELDS
from .ctap_encode import (
    _determine_ctap_prefix,
    _encode_ctap_from_decoded,
    _encode_ctap_from_structure,
    _encode_get_assertion_request,
    _encode_get_assertion_response,
    _encode_make_credential_request,
    _encode_make_credential_response,
)
from .ctap_numeric import _extract_ctap_numeric_payload, _normalize_ctap_extra_value
from .handlers_basic import _prepare_encoder_response


def _encode_cbor_value(parsed: Any, *, base_type: str = "CBOR (canonical)") -> Dict[str, Any]:
    ctap_source: Optional[Mapping[str, Any]] = None
    ctap_kind: Optional[str] = None
    ctap_metadata: Optional[Mapping[str, Any]] = None
    encoded_map: Optional[Mapping[Any, Any]] = None

    if isinstance(parsed, Mapping):
        ctap_metadata = parsed.get("ctap") if isinstance(parsed.get("ctap"), Mapping) else None

        ctap_decoded = parsed.get("ctapDecoded")
        if isinstance(ctap_decoded, Mapping):
            encoded_map, ctap_kind = _encode_ctap_from_decoded(ctap_decoded)
            if encoded_map is not None:
                ctap_source = ctap_decoded.get(ctap_kind) if isinstance(ctap_decoded.get(ctap_kind), Mapping) else ctap_decoded

        if encoded_map is None:
            expanded = parsed.get("expandedJson")
            if isinstance(expanded, Mapping):
                encoded_map, ctap_kind = _encode_ctap_from_structure(expanded)
                if encoded_map is not None:
                    ctap_source = expanded

        if encoded_map is None:
            encoded_map, ctap_kind = _encode_ctap_from_structure(parsed)
            if encoded_map is not None:
                ctap_source = parsed

    if encoded_map is not None:
        prefix_code, prefix_kind = _determine_ctap_prefix(ctap_metadata, ctap_kind)
        payload_bytes = _canonical_cbor_dumps(encoded_map)
        full_bytes = (
            bytes([prefix_code]) + payload_bytes if prefix_code is not None else payload_bytes
        )
        canonical_structure = _canonicalize_cbor_structure(encoded_map)
        payload: Dict[str, Any] = {
            "binary": _binary_summary(full_bytes, "cbor"),
            "encodedValue": _stringify_mapping_keys(
                _hex_json_safe(canonical_structure)
            ),
        }
        if ctap_source is not None and isinstance(ctap_source, Mapping):
            canonical_ctap_source = _canonicalize_cbor_structure(ctap_source)
            payload.setdefault(
                "ctapDecoded",
                _stringify_mapping_keys(
                    _hex_json_safe({ctap_kind: canonical_ctap_source})
                )
                if ctap_kind
                else _stringify_mapping_keys(_hex_json_safe(canonical_ctap_source)),
            )
        if prefix_code is not None:
            payload["ctap"] = {
                "code": prefix_code,
                "codeHex": f"0x{prefix_code:02x}",
                "kind": prefix_kind,
            }
        qualifier = f"encoded {ctap_kind}" if ctap_kind else "encoded"
        return _prepare_encoder_response(base_type, payload, qualifier=qualifier)

    payload_bytes = _canonical_cbor_dumps(parsed)
    payload = {
        "binary": _binary_summary(payload_bytes, "cbor"),
        "decodedValue": _stringify_mapping_keys(
            _hex_json_safe(_canonicalize_cbor_structure(parsed))
        ),
    }
    return _prepare_encoder_response(base_type, payload, qualifier="encoded")


def _encode_ctap_webauthn_value(parsed: Any) -> Dict[str, Any]:
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

    extras: Dict[int, Any] = {}
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

    payload: Dict[str, Any] = {
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


def _encode_cose_value(parsed: Any) -> Dict[str, Any]:
    return _encode_cbor_value(parsed, base_type="COSE")
