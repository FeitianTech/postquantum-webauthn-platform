"""Encoding helpers for the codec pipeline."""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import string
import struct
import textwrap
from collections import deque
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import cbor2
from cbor2 import CBORTag, CBORSimpleValue, undefined

from ..attestation import make_json_safe, serialize_attestation_certificate
from .decode import (
    _binary_summary,
    _describe_authenticator_data_bytes,
    _hex_json_safe,
    _parse_attestation_object,
    _stringify_mapping_keys,
)

__all__ = ["encode_payload_text"]


_CTAP_LABELED_KEY_PATTERN = re.compile(r"^\s*(-?\d+)\s*\(([^)]+)\)\s*$")

_CTAP_FIELD_LABELS: Dict[str, Dict[int, str]] = {
    "makeCredentialRequest": {
        1: "clientDataHash",
        2: "rp",
        3: "user",
        4: "pubKeyCredParams",
        5: "excludeList",
        6: "extensions",
        7: "options",
        8: "pinUvAuthParam",
        9: "pinUvAuthProtocol",
        10: "enterpriseAttestation",
        11: "largeBlobKey",
    },
    "getAssertionRequest": {
        1: "rpId",
        2: "clientDataHash",
        3: "allowList",
        4: "extensions",
        5: "options",
        6: "pinUvAuthParam",
        7: "pinUvAuthProtocol",
        8: "largeBlobKey",
    },
    "makeCredentialResponse": {
        1: "fmt",
        2: "authData",
        3: "attStmt",
        4: "epAtt",
        5: "largeBlobKey",
        6: "extensions",
    },
    "getAssertionResponse": {
        1: "credential",
        2: "authData",
        3: "signature",
        4: "user",
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
    },
}

_CTAP_REQUIRED_FIELDS: Dict[str, Sequence[int]] = {
    "makeCredentialRequest": (1, 2, 3, 4),
    "getAssertionRequest": (1, 2),
    "makeCredentialResponse": (1, 2),
    "getAssertionResponse": (2, 3),
}

_CTAP_PREFIX_DETAILS: Dict[str, Tuple[int, str]] = {
    "makeCredentialRequest": (0x01, "command"),
    "getAssertionRequest": (0x02, "command"),
    "makeCredentialResponse": (0x00, "status"),
    "getAssertionResponse": (0x00, "status"),
}


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


def _extract_ctap_numeric_payload(parsed: Any) -> Tuple[Dict[int, Any], str]:
    """Locate and sanitize a CTAP/WebAuthn numeric-keyed mapping within ``parsed``."""

    def _enqueue_candidates(queue: deque[Any], value: Any, visited: set[int]) -> None:
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in visited:
                return
            visited.add(marker)
            queue.append(value)
            return

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for entry in value:
                _enqueue_candidates(queue, entry, visited)

    visited: set[int] = set()
    candidates: deque[Any] = deque()
    _enqueue_candidates(candidates, parsed, visited)

    classification_error: Optional[ValueError] = None

    while candidates:
        candidate = candidates.popleft()

        try:
            numeric_map = _sanitize_ctap_numeric_mapping(candidate)
        except ValueError:
            None
            salvage_map: Dict[int, Any] = {}
            salvage_error: Optional[ValueError] = None
            if isinstance(candidate, Mapping):
                for key, value in candidate.items():
                    try:
                        index = _coerce_ctap_numeric_key(key)
                    except ValueError as exc:
                        salvage_map = {}
                        salvage_error = exc
                        break
                    if index is None:
                        continue
                    if index in salvage_map:
                        salvage_map = {}
                        salvage_error = ValueError(
                            f"Duplicate field 0x{index:02x} detected in CTAP/WebAuthn input."
                        )
                        break
                    salvage_map[index] = value

            if salvage_map:
                try:
                    ctap_type = _classify_ctap_numeric_mapping(salvage_map)
                except ValueError as exc:
                    if classification_error is None:
                        classification_error = exc
                else:
                    return salvage_map, ctap_type

            if salvage_error is not None and classification_error is None:
                classification_error = salvage_error
        else:
            try:
                ctap_type = _classify_ctap_numeric_mapping(numeric_map)
            except ValueError as exc:
                if classification_error is None:
                    classification_error = exc
            else:
                return numeric_map, ctap_type

        if isinstance(candidate, Mapping):
            for value in candidate.values():
                _enqueue_candidates(candidates, value, visited)

    if classification_error is not None:
        raise classification_error

    raise ValueError(
        "Unable to locate CTAP/WebAuthn numeric-keyed fields in input JSON."
    )


def _sanitize_ctap_numeric_mapping(parsed: Mapping[Any, Any]) -> Dict[int, Any]:
    numeric_map: Dict[int, Any] = {}
    for key, value in parsed.items():
        index = _coerce_ctap_numeric_key(key)
        if index is None:
            raise ValueError(
                "CTAP/WebAuthn encoding requires numeric keys such as \"01\" or \"02\"."
            )
        if index in numeric_map:
            raise ValueError(f"Duplicate field 0x{index:02x} detected in CTAP/WebAuthn input.")
        numeric_map[index] = value

    if not numeric_map:
        raise ValueError("CTAP/WebAuthn encoding expects at least one CTAP field.")

    return numeric_map


def _coerce_ctap_numeric_key(key: Any) -> Optional[int]:
    if isinstance(key, int):
        index = key
    elif isinstance(key, str):
        stripped = key.strip()
        if not stripped:
            return None
        match = _CTAP_LABELED_KEY_PATTERN.match(stripped)
        if match:
            stripped = match.group(1).strip()
        if stripped.lower().startswith("0x"):
            try:
                index = int(stripped, 16)
            except ValueError:
                return None
        elif stripped.isdigit():
            index = int(stripped, 10)
        else:
            return None
    else:
        return None

    if index < 0:
        raise ValueError(
            f"CTAP/WebAuthn field numbers must be non-negative (received {index})."
        )
    return index


def _classify_ctap_numeric_mapping(mapping: Mapping[int, Any]) -> str:
    if not mapping:
        raise ValueError("CTAP/WebAuthn encoding expects at least one CTAP field.")

    field_two = mapping.get(2)
    if field_two is None:
        raise ValueError("Missing field 0x02 (authData/clientDataHash/rp)")

    signature_candidate = mapping.get(3)
    signature_bytes = (
        _maybe_decode_bytes(signature_candidate) if signature_candidate is not None else None
    )
    if signature_bytes is not None:
        field_two_bytes = _maybe_decode_bytes(field_two)
        if field_two_bytes is None:
            raise ValueError(
                "Field 0x02 (authData) must be binary data for GetAssertion response."
            )
        if len(field_two_bytes) < 37:
            raise ValueError(
                "Field 0x02 (authData) must contain authenticator data for GetAssertion response."
            )
        return "getAssertionResponse"

    field_one = mapping.get(1)
    if field_one is None:
        raise ValueError("Missing field 0x01 (clientDataHash/rpId/fmt/credential)")

    field_one_bytes = _maybe_decode_bytes(field_one)
    if field_one_bytes is not None:
        if len(field_one_bytes) != 32:
            raise ValueError(
                "Field 0x01 (clientDataHash) must be exactly 32 bytes for MakeCredential request."
            )
        if not isinstance(field_two, Mapping):
            raise ValueError("Field 0x02 (rp) must be an object for MakeCredential request.")
        return "makeCredentialRequest"

    if isinstance(field_one, str) and field_one.strip():
        field_two_bytes = _maybe_decode_bytes(field_two)
        if field_two_bytes is None:
            raise ValueError(
                "Field 0x02 (authData/clientDataHash) must be binary data."
            )
        if len(field_two_bytes) == 32:
            return "getAssertionRequest"
        if len(field_two_bytes) >= 37:
            return "makeCredentialResponse"
        raise ValueError(
            "Field 0x02 (authData/clientDataHash) length is not valid for CTAP/WebAuthn data."
        )

    raise ValueError(
        "Unable to classify CTAP/WebAuthn data. Provide MakeCredential/GetAssertion request or response fields."
    )


def _normalize_ctap_extra_value(value: Any) -> Any:
    decoded = _maybe_decode_bytes(value)
    if decoded is not None:
        return decoded

    if isinstance(value, Mapping):
        cleaned: Dict[str, Any] = {}
        for key, entry in value.items():
            cleaned[_sanitize_nested_extra_key(key)] = _normalize_ctap_extra_value(entry)
        return cleaned

    if isinstance(value, list):
        return [_normalize_ctap_extra_value(entry) for entry in value]

    return value


def _sanitize_nested_extra_key(key: Any) -> str:
    if isinstance(key, str):
        stripped = key.strip()
        if not stripped:
            return ""
        match = _CTAP_LABELED_KEY_PATTERN.match(stripped)
        if match:
            label = match.group(2).strip()
            if label:
                return label
            stripped = match.group(1).strip()
        return stripped
    return str(key)


def _encode_hex_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "hex")
    payload = {
        "binary": summary,
        "hex": summary["hex"],
    }
    return _prepare_encoder_response("Hex", payload, qualifier="encoded")


def _encode_base64_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "base64")
    payload = {
        "binary": summary,
        "base64": summary["base64"],
    }
    return _prepare_encoder_response("Base64", payload, qualifier="encoded")


def _encode_base64url_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "base64url")
    payload = {
        "binary": summary,
        "base64url": summary["base64url"],
    }
    return _prepare_encoder_response("Base64URL", payload, qualifier="encoded")


def _encode_binary_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "binary")
    payload = {
        "binary": summary,
        "bytes": list(data_bytes),
    }
    return _prepare_encoder_response("Binary data", payload, qualifier="raw bytes")


def _encode_der_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "der")
    payload = {
        "binary": summary,
        "derBase64": summary["base64"],
    }
    return _prepare_encoder_response("DER", payload, qualifier="encoded")


def _encode_pem_value(parsed: Any) -> Dict[str, Any]:
    data_bytes = _extract_generic_binary_payload(parsed)
    summary = _binary_summary(data_bytes, "pem")
    label = _determine_pem_label(parsed)
    payload = {
        "binary": summary,
        "pem": _format_pem_block(summary["base64"], label),
    }
    return _prepare_encoder_response("PEM", payload, qualifier="encoded")


def _encode_cose_value(parsed: Any) -> Dict[str, Any]:
    return _encode_cbor_value(parsed, base_type="COSE")


def _extract_generic_binary_payload(value: Any) -> bytes:
    queue: deque[Any] = deque([value])
    seen: set[int] = set()

    while queue:
        candidate = queue.popleft()
        decoded = _maybe_decode_bytes(candidate)
        if decoded is not None:
            return decoded

        if isinstance(candidate, Mapping):
            marker = id(candidate)
            if marker in seen:
                continue
            seen.add(marker)

            preferred_keys = (
                "value",
                "data",
                "raw",
                "binary",
                "bytes",
                "payload",
                "body",
                "der",
                "derBase64",
                "pem",
                "base64",
                "base64url",
            )
            for key in preferred_keys:
                if key in candidate:
                    queue.append(candidate[key])

            for entry in candidate.values():
                if isinstance(entry, (Mapping, Sequence)) and not isinstance(entry, (str, bytes, bytearray)):
                    queue.append(entry)
        elif isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
            queue.extend(candidate)

    raise ValueError("Unable to extract binary payload for encoding.")


def _determine_pem_label(value: Any) -> str:
    if isinstance(value, Mapping):
        for key in ("pemLabel", "label"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                return entry

        binary_section = value.get("binary")
        if isinstance(binary_section, Mapping):
            encoding_label = binary_section.get("encoding")
            if isinstance(encoding_label, str) and encoding_label.strip():
                return encoding_label

    return "DATA"


def _format_pem_block(base64_body: str, label: str) -> str:
    normalized_label = _normalize_pem_label(label)
    wrapped = "\n".join(textwrap.wrap(base64_body, 64)) if base64_body else ""
    return f"-----BEGIN {normalized_label}-----\n{wrapped}\n-----END {normalized_label}-----"


def _normalize_pem_label(label: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]+", " ", label).strip()
    if not sanitized:
        return "DATA"
    compact = re.sub(r"\s+", " ", sanitized)
    return compact.replace(" ", "_").upper()


def _canonical_cbor_dumps(value: Any) -> bytes:
    """Serialize *value* using strict canonical CBOR rules."""

    return cbor2.dumps(value, canonical=True)


def _canonicalize_cbor_structure(value: Any) -> Any:
    """Return a structure whose maps follow canonical CBOR key ordering."""

    encoder = _CanonicalCBOREncoder()
    return encoder.canonicalize_structure(value)


class _CanonicalCBOREncoder:
    """Minimal canonical CBOR encoder specialised for deterministic output."""

    def encode(self, value: Any) -> bytes:
        return self._encode(value)

    def canonicalize_structure(self, value: Any) -> Any:
        return self._canonicalize(value)

    def _encode(self, value: Any) -> bytes:
        if isinstance(value, Mapping):
            return self._encode_map(value)
        if isinstance(value, CBORSimpleValue):
            return self._encode_cbor_simple_value(value)
        if isinstance(value, (list, tuple)):
            return self._encode_array(value)
        if isinstance(value, CBORTag):
            return self._encode_tag(value)
        return self._encode_simple(value)

    def _canonicalize(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return self._canonicalize_map(value)
        if isinstance(value, (list, tuple)):
            return [self._canonicalize(item) for item in value]
        if isinstance(value, CBORTag):
            return CBORTag(value.tag, self._canonicalize(value.value))
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        return value

    def _encode_simple(self, value: Any) -> bytes:
        if isinstance(value, bool):
            return b"\xf5" if value else b"\xf4"
        if value is None:
            return b"\xf6"
        if value is undefined:
            return b"\xf7"
        if isinstance(value, int):
            return self._encode_int(value)
        if isinstance(value, float):
            return _encode_canonical_float(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return self._encode_bytes(value)
        if isinstance(value, str):
            return self._encode_text(value)
        if isinstance(value, CBORSimpleValue):
            return self._encode_cbor_simple_value(value)

        # Fall back to cbor2 for less common types (e.g. decimal.Decimal, datetime).
        # The canonical flag preserves determinism while allowing extended values.
        return cbor2.dumps(value, canonical=True)

    def _encode_array(self, values: Iterable[Any]) -> bytes:
        encoded_items = [self._encode(item) for item in values]
        prefix = _encode_major_type_with_length(4, len(encoded_items))
        return prefix + b"".join(encoded_items)

    def _encode_bytes(self, value: Any) -> bytes:
        data = bytes(value)
        prefix = _encode_major_type_with_length(2, len(data))
        return prefix + data

    def _encode_map(self, mapping: Mapping[Any, Any]) -> bytes:
        sorted_items = self._sorted_map_items(mapping)
        prefix = _encode_major_type_with_length(5, len(sorted_items))
        chunks = []
        for encoded_key, _original_key, value in sorted_items:
            encoded_value = self._encode(value)
            chunks.append(encoded_key + encoded_value)
        return prefix + b"".join(chunks)

    def _canonicalize_map(self, mapping: Mapping[Any, Any]) -> Dict[Any, Any]:
        sorted_items = self._sorted_map_items(mapping)
        result: Dict[Any, Any] = {}
        for _encoded_key, key, value in sorted_items:
            result[key] = self._canonicalize(value)
        return result

    def _sorted_map_items(
        self, mapping: Mapping[Any, Any]
    ) -> List[Tuple[bytes, Any, Any]]:
        encoded_items: List[Tuple[bytes, Any, Any]] = []
        seen_keys: set[bytes] = set()
        for key, value in mapping.items():
            encoded_key = self._encode(key)
            if encoded_key in seen_keys:
                raise ValueError(
                    "Duplicate CBOR map key detected during canonical encoding."
                )
            seen_keys.add(encoded_key)
            encoded_items.append((encoded_key, key, value))

        encoded_items.sort(key=lambda item: (len(item[0]), item[0]))
        return encoded_items

    def _encode_tag(self, tag: CBORTag) -> bytes:
        if not isinstance(tag.tag, int) or tag.tag < 0:
            raise ValueError("CBOR tags must be non-negative integers.")
        encoded_tag = _encode_unsigned_integer(6, tag.tag)
        encoded_value = self._encode(tag.value)
        return encoded_tag + encoded_value

    def _encode_int(self, value: int) -> bytes:
        if value >= 0:
            return _encode_unsigned_integer(0, value)

        complement = -1 - value
        return _encode_unsigned_integer(1, complement)

    def _encode_text(self, value: str) -> bytes:
        data = value.encode("utf-8")
        prefix = _encode_major_type_with_length(3, len(data))
        return prefix + data

    def _encode_cbor_simple_value(self, value: CBORSimpleValue) -> bytes:
        simple = value.value
        if not isinstance(simple, int):
            raise TypeError("CBOR simple value code must be an integer.")
        if simple < 0 or simple > 255:
            raise ValueError("CBOR simple value code must be between 0 and 255.")

        if simple <= 23:
            return bytes([0xE0 | simple])
        if 32 <= simple <= 255:
            return b"\xf8" + bytes([simple])

        raise ValueError("CBOR simple values 24..31 are reserved in canonical encoding.")


def _encode_major_type_with_length(major_type: int, length: int) -> bytes:
    if length < 0:
        raise ValueError("CBOR lengths must be non-negative.")
    return _encode_unsigned_integer(major_type, length)


def _encode_unsigned_integer(major_type: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("Unsigned CBOR integers must be non-negative.")

    if value < 24:
        return bytes([(major_type << 5) | value])
    if value < 256:
        return bytes([(major_type << 5) | 24, value])
    if value < 65536:
        return bytes([(major_type << 5) | 25]) + value.to_bytes(2, "big")
    if value < 4294967296:
        return bytes([(major_type << 5) | 26]) + value.to_bytes(4, "big")
    if value < 18446744073709551616:
        return bytes([(major_type << 5) | 27]) + value.to_bytes(8, "big")

    raise ValueError("CBOR integers exceeding 64 bits are not supported in canonical mode.")


def _encode_canonical_float(value: float) -> bytes:
    if math.isnan(value):
        # Canonical NaN representation (RFC 8949, Section 3.9): 0xf9 7e00
        return b"\xf9\x7e\x00"

    for fmt, prefix in (("e", b"\xf9"), ("f", b"\xfa"), ("d", b"\xfb")):
        try:
            packed = struct.pack(">" + fmt, value)
        except (OverflowError, ValueError):
            continue

        unpacked = struct.unpack(">" + fmt, packed)[0]
        if math.isnan(unpacked):
            continue

        if unpacked == value and math.copysign(1.0, unpacked) == math.copysign(1.0, value):
            return prefix + packed

    # Fall back to float64 encoding when no shorter representation is exact.
    return b"\xfb" + struct.pack(">d", value)


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


def _extract_binary_input(value: Any, field_name: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, Mapping):
        if field_name in value:
            return _require_bytes(value[field_name], field_name)

        for candidate in ("raw", "hex", "value", "data", "bytes"):
            if candidate in value:
                decoded = _maybe_decode_bytes(value[candidate])
                if decoded is not None:
                    return decoded

        for candidate in ("base64", "base64url", "derBase64", "pem"):
            if candidate in value:
                decoded = _maybe_decode_bytes(value[candidate])
                if decoded is not None:
                    return decoded

    if isinstance(value, str):
        decoded = _maybe_decode_bytes(value)
        if decoded is not None:
            return decoded

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if all(isinstance(item, int) and 0 <= item < 256 for item in value):
            return bytes(value)

    raise ValueError(f"Unable to interpret {field_name} as binary data for encoding.")


def _encode_ctap_from_decoded(
    decoded: Mapping[str, Any]
) -> Tuple[Optional[Dict[int, Any]], Optional[str]]:
    if not isinstance(decoded, Mapping):
        return None, None

    for key in (
        "makeCredentialRequest",
        "getAssertionRequest",
        "makeCredentialResponse",
        "getAssertionResponse",
    ):
        entry = decoded.get(key)
        if isinstance(entry, Mapping):
            encoded_map, kind = _encode_ctap_from_structure(entry)
            if encoded_map is not None:
                return encoded_map, key
    return None, None


def _encode_ctap_from_structure(
    structure: Mapping[str, Any]
) -> Tuple[Optional[Dict[int, Any]], Optional[str]]:
    if not isinstance(structure, Mapping):
        return None, None

    if _get_ctap_field_value(structure, "fmt", 1) is not None and _get_ctap_field_value(structure, "authData", 2) is not None:
        return _encode_make_credential_response(structure), "makeCredentialResponse"

    if _get_ctap_field_value(structure, "credential", 1) is not None or _get_ctap_field_value(structure, "signature", 3) is not None:
        return _encode_get_assertion_response(structure), "getAssertionResponse"

    if _get_ctap_field_value(structure, "rp", 2) is not None and _get_ctap_field_value(structure, "user", 3) is not None:
        return _encode_make_credential_request(structure), "makeCredentialRequest"

    if _get_ctap_field_value(structure, "rpId", 1) is not None and _get_ctap_field_value(structure, "clientDataHash", 2) is not None:
        return _encode_get_assertion_request(structure), "getAssertionRequest"

    return None, None


def _determine_ctap_prefix(
    metadata: Optional[Mapping[str, Any]], kind: Optional[str]
) -> Tuple[Optional[int], Optional[str]]:
    if isinstance(metadata, Mapping):
        code = metadata.get("code")
        if not isinstance(code, int):
            code_hex = metadata.get("codeHex")
            if isinstance(code_hex, str):
                try:
                    code = int(code_hex, 16)
                except ValueError:
                    code = None
        kind_hint = metadata.get("kind") if isinstance(metadata.get("kind"), str) else None
        if isinstance(code, int) and 0 <= code <= 0xFF:
            return code, kind_hint

    defaults = {
        "makeCredentialRequest": (0x01, "command"),
        "getAssertionRequest": (0x02, "command"),
        "makeCredentialResponse": (0x00, "status"),
        "getAssertionResponse": (0x00, "status"),
    }
    if kind in defaults:
        return defaults[kind]

    return None, None


def _encode_make_credential_request(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _require_bytes(_get_ctap_field_value(structure, "clientDataHash", 1), "clientDataHash")
    mapping[2] = _restore_generic_structure(
        _require_mapping(_get_ctap_field_value(structure, "rp", 2), "rp")
    )
    mapping[3] = _encode_ctap_user(_get_ctap_field_value(structure, "user", 3))

    params = _get_ctap_field_value(structure, "pubKeyCredParams", 4)
    if params is None:
        raise ValueError("MakeCredential request requires pubKeyCredParams.")
    mapping[4] = _restore_generic_structure(params)

    exclude_list = _get_ctap_field_value(structure, "excludeList", 5)
    if exclude_list is not None:
        mapping[5] = _encode_allow_list(exclude_list)

    extensions = _get_ctap_field_value(structure, "extensions", 6)
    if extensions is not None:
        mapping[6] = _restore_generic_structure(extensions)

    options = _get_ctap_field_value(structure, "options", 7)
    if options is not None:
        mapping[7] = _restore_generic_structure(options)

    pin_param = _get_ctap_field_value(structure, "pinUvAuthParam", 8)
    if pin_param is not None:
        mapping[8] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = _get_ctap_field_value(structure, "pinUvAuthProtocol", 9)
    if pin_protocol is not None:
        mapping[9] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    enterprise_attestation = _get_ctap_field_value(structure, "enterpriseAttestation", 10)
    if enterprise_attestation is not None:
        mapping[10] = _restore_generic_structure(enterprise_attestation)

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 11)
    if large_blob_key is not None:
        mapping[11] = _require_bytes(large_blob_key, "largeBlobKey")

    return mapping


def _encode_get_assertion_request(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _ensure_text(
        _get_ctap_field_value(structure, "rpId", 1), "rpId"
    )
    mapping[2] = _require_bytes(
        _get_ctap_field_value(structure, "clientDataHash", 2), "clientDataHash"
    )

    allow_list = _get_ctap_field_value(structure, "allowList", 3)
    if allow_list is not None:
        mapping[3] = _encode_allow_list(allow_list)

    extensions = _get_ctap_field_value(structure, "extensions", 4)
    if extensions is not None:
        mapping[4] = _restore_generic_structure(extensions)

    options = _get_ctap_field_value(structure, "options", 5)
    if options is not None:
        mapping[5] = _restore_generic_structure(options)

    pin_param = _get_ctap_field_value(structure, "pinUvAuthParam", 6)
    if pin_param is not None:
        mapping[6] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = _get_ctap_field_value(structure, "pinUvAuthProtocol", 7)
    if pin_protocol is not None:
        mapping[7] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 8)
    if large_blob_key is not None:
        mapping[8] = _require_bytes(large_blob_key, "largeBlobKey")

    return mapping


def _encode_make_credential_response(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _ensure_text(_get_ctap_field_value(structure, "fmt", 1), "fmt")
    mapping[2] = _require_bytes(_get_ctap_field_value(structure, "authData", 2), "authData")

    att_stmt = _get_ctap_field_value(structure, "attStmt", 3)
    if att_stmt is not None:
        mapping[3] = _encode_attestation_statement(att_stmt)

    ep_att = _get_ctap_field_value(structure, "epAtt", 4)
    if ep_att is not None:
        mapping[4] = _restore_generic_structure(ep_att)

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 5)
    if large_blob_key is not None:
        mapping[5] = _require_bytes(large_blob_key, "largeBlobKey")

    extensions = _get_ctap_field_value(structure, "extensions", 6)
    if extensions is not None:
        mapping[6] = _restore_generic_structure(extensions)

    return mapping


def _encode_get_assertion_response(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    credential = _get_ctap_field_value(structure, "credential", 1)
    if credential is not None:
        mapping[1] = _encode_credential_descriptor(credential)

    mapping[2] = _require_bytes(_get_ctap_field_value(structure, "authData", 2), "authData")
    mapping[3] = _require_bytes(_get_ctap_field_value(structure, "signature", 3), "signature")

    user = _get_ctap_field_value(structure, "user", 4)
    if user is not None:
        mapping[4] = _encode_ctap_user(user)

    number_of_credentials = _get_ctap_field_value(structure, "numberOfCredentials", 5)
    if number_of_credentials is not None:
        mapping[5] = _ensure_int(number_of_credentials, "numberOfCredentials")

    user_selected = _get_ctap_field_value(structure, "userSelected", 6)
    if user_selected is not None:
        mapping[6] = _ensure_bool(user_selected, "userSelected")

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 7)
    if large_blob_key is not None:
        mapping[7] = _require_bytes(large_blob_key, "largeBlobKey")

    extensions = _get_ctap_field_value(structure, "extensions", 8)
    if extensions is not None:
        mapping[8] = _restore_generic_structure(extensions)

    return mapping


def _get_ctap_field_value(structure: Mapping[str, Any], label: str, index: Optional[int] = None) -> Any:
    candidates = {label.lower()}
    if index is not None:
        candidates.add(str(index))
        candidates.add(f"{index} ({label})")

    for key, value in structure.items():
        if _ctap_key_matches(key, candidates):
            return value
    return None


def _ctap_key_matches(key: Any, candidates: Iterable[str]) -> bool:
    key_str = str(key).strip()
    key_lower = key_str.lower()
    normalized_candidates = {candidate.strip() for candidate in candidates}
    normalized_lower = {candidate.lower() for candidate in normalized_candidates}

    if key_str in normalized_candidates or key_lower in normalized_lower:
        return True

    if isinstance(key, str):
        match = _CTAP_LABELED_KEY_PATTERN.match(key)
        if match:
            number = match.group(1).strip()
            label = match.group(2).strip()
            if number in normalized_candidates or number.lower() in normalized_lower:
                return True
            if label in normalized_candidates or label.lower() in normalized_lower:
                return True
    return False


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise ValueError(f"{field_name} must be an object for encoding.")


def _ensure_text(value: Any, field_name: str) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    raise ValueError(f"{field_name} must be a non-empty string.")


def _ensure_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not a boolean.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer value.") from exc
    raise ValueError(f"{field_name} must be an integer value.")


def _ensure_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    raise ValueError(f"{field_name} must be a boolean value.")


def _encode_attestation_statement(value: Any) -> Any:
    if value is None:
        return None

    if not isinstance(value, Mapping):
        return _require_bytes(value, "attStmt")

    statement: Dict[str, Any] = {}
    for key, entry in value.items():
        if key == "sig":
            statement["sig"] = _require_bytes(entry, "attStmt.sig")
        elif key == "x5c":
            if not isinstance(entry, Sequence):
                raise ValueError("attStmt.x5c must be an array of certificates.")
            statement["x5c"] = [
                _require_certificate_bytes(item, index)
                for index, item in enumerate(entry)
            ]
        else:
            decoded = _maybe_decode_bytes(entry)
            statement[key] = decoded if decoded is not None else _restore_generic_structure(entry)
    return statement


def _require_certificate_bytes(entry: Any, index: int) -> bytes:
    decoded = _maybe_decode_bytes(entry)
    if decoded is not None:
        return decoded
    if isinstance(entry, Mapping):
        pem = entry.get("pem")
        if isinstance(pem, str) and pem.strip():
            body = "".join(re.findall(r"[A-Za-z0-9+/=]", pem))
            try:
                return base64.b64decode(body)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Unable to decode certificate PEM contents.") from exc
    raise ValueError(f"Unable to recover certificate bytes for x5c[{index}].")


def _encode_ctap_user(value: Any) -> Dict[str, Any]:
    mapping = _require_mapping(value, "user")
    result: Dict[str, Any] = {}

    if "id" in mapping:
        result["id"] = _require_bytes(mapping["id"], "user.id")
    if "name" in mapping:
        result["name"] = _ensure_text(mapping["name"], "user.name")
    if "displayName" in mapping:
        result["displayName"] = _ensure_text(mapping["displayName"], "user.displayName")
    if "icon" in mapping and mapping["icon"] is not None:
        result["icon"] = _ensure_text(str(mapping["icon"]), "user.icon")

    for key, entry in mapping.items():
        if key in {"id", "name", "displayName", "icon"}:
            continue
        decoded = _maybe_decode_bytes(entry)
        result[str(key)] = decoded if decoded is not None else _restore_generic_structure(entry)

    return result


def _encode_allow_list(value: Any) -> List[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_encode_credential_descriptor(item) for item in value]
    raise ValueError("allowList must be an array of credential descriptors.")


def _encode_credential_descriptor(value: Any) -> Any:
    decoded = _maybe_decode_bytes(value)
    if decoded is not None:
        return decoded

    mapping = _require_mapping(value, "credential descriptor")
    descriptor: Dict[str, Any] = {}

    if "type" in mapping:
        descriptor["type"] = _ensure_text(mapping["type"], "credential.type")
    if "id" in mapping:
        descriptor["id"] = _require_bytes(mapping["id"], "credential.id")
    if "transports" in mapping:
        descriptor["transports"] = _restore_generic_structure(mapping["transports"])

    for key, entry in mapping.items():
        if key in {"type", "id", "transports"}:
            continue
        decoded_entry = _maybe_decode_bytes(entry)
        descriptor[str(key)] = decoded_entry if decoded_entry is not None else _restore_generic_structure(entry)

    return descriptor


def _restore_generic_structure(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _restore_generic_structure(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_restore_generic_structure(item) for item in value]
    return value


def _require_bytes(value: Any, field_name: str) -> bytes:
    decoded = _maybe_decode_bytes(value)
    if decoded is None:
        raise ValueError(f"Unable to interpret {field_name} as binary data.")
    return decoded


def _maybe_decode_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        hex_candidate = candidate.replace(":", "")
        if len(hex_candidate) % 2 == 0 and hex_candidate and all(
            char in string.hexdigits for char in hex_candidate
        ):
            try:
                return bytes.fromhex(hex_candidate)
            except ValueError:
                pass

        cleaned = "".join(candidate.split())
        if cleaned:
            padding = (-len(cleaned)) % 4
            for decoder, encoder in (
                (base64.b64decode, base64.b64encode),
                (base64.urlsafe_b64decode, base64.urlsafe_b64encode),
            ):
                try:
                    decoded = decoder(cleaned + "=" * padding)
                except (ValueError, binascii.Error):
                    continue

                # Confirm the round-trip to avoid misclassifying plain text as base64.
                try:
                    reencoded = encoder(decoded).decode("ascii").rstrip("=")
                except Exception:  # pragma: no cover - defensive
                    continue
                if reencoded == cleaned.rstrip("="):
                    return decoded

    if isinstance(value, Mapping):
        for key in ("raw", "hex", "hexValue", "hexString"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                try:
                    return bytes.fromhex(entry.replace(":", ""))
                except ValueError:
                    continue

        for key in ("base64", "derBase64", "valueBase64"):
            entry = value.get(key)
            if isinstance(entry, str) and entry.strip():
                cleaned = "".join(entry.split())
                padding = (-len(cleaned)) % 4
                try:
                    return base64.b64decode(cleaned + "=" * padding)
                except (ValueError, binascii.Error):
                    continue

        entry = value.get("base64url")
        if isinstance(entry, str) and entry.strip():
            cleaned = "".join(entry.split())
            padding = (-len(cleaned)) % 4
            try:
                return base64.urlsafe_b64decode(cleaned + "=" * padding)
            except (ValueError, binascii.Error):
                pass

        bytes_field = value.get("bytes")
        if isinstance(bytes_field, Sequence) and all(
            isinstance(item, int) and 0 <= item < 256 for item in bytes_field
        ):
            return bytes(bytes_field)

        pem_value = value.get("pem")
        if isinstance(pem_value, str) and pem_value.strip():
            body = "".join(re.findall(r"[A-Za-z0-9+/=]", pem_value))
            if body:
                padding = (-len(body)) % 4
                try:
                    return base64.b64decode(body + "=" * padding)
                except (ValueError, binascii.Error):
                    pass

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if all(isinstance(item, int) and 0 <= item < 256 for item in value):
            return bytes(value)

    return None
