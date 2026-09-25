"""Encode a COSE_Key given as JSON, with the integer labels COSE uses.

JSON has only text keys and no byte strings, so a COSE key arrives with labels
spelled "1", "-2" or "-2 (x)" and its byte-string parameters as hex or base64url
text -- the decoder shows both. Labels become integers again, and a parameter
the COSE registries (``cose_tables``) type as a byte string is decoded from its
text, strictly, the way every other binary field is (``encoding.sniff``: hex,
then base64url, then base64). A string under a label the registries do not
type is refused rather than guessed at: it could have been text or bytes.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ... import encoding
from .. import cose_tables
from ..cbor_canonical import _canonical_cbor_dumps
from ..decode import _binary_summary, _hex_json_safe, _stringify_mapping_keys
from .handlers_basic import _prepare_encoder_response

_LABEL = re.compile(r"^\s*(-?\d+)\s*(?:\([^()]*\))?\s*$")


def encode_cose_key(parsed: Any) -> dict[str, Any]:
    key, ignored = _cose_member(parsed)
    labelled: dict[int, Any] = {}
    for raw_label, value in key.items():
        label = _label(raw_label)
        if label in labelled:
            raise ValueError(f"COSE key label {label} is given twice.")
        labelled[label] = value

    kty = labelled.get(1)
    if kty is None:
        raise ValueError("A COSE_Key needs kty (label 1): RFC 9052 section 7.1.")
    if isinstance(kty, bool) or not isinstance(kty, (int, str)):
        # RFC 9052 section 7.1: kty is tstr / int. A list or an object would not even look up.
        raise ValueError(f"COSE key kty (label 1) is an integer or text, not {type(kty).__name__}: RFC 9052 section 7.1.")
    parameters = {**cose_tables.COMMON_PARAMETERS, **cose_tables.KEY_TYPE_PARAMETERS.get(kty, {})}
    cose_key = {label: _value(label, value, parameters, kty) for label, value in labelled.items()}

    encoded = _canonical_cbor_dumps(cose_key)
    payload = {
        "binary": _binary_summary(encoded, "cbor"),
        "encodedValue": _stringify_mapping_keys(_hex_json_safe(cose_key)),
    }
    warnings = []
    if ignored:
        warnings.append(
            f"Encoded only cose; {', '.join(sorted(ignored))} beside it "
            "were not encoded (the decoder's descriptions of the key)."
        )
    return _prepare_encoder_response("COSE", payload, qualifier="COSE_Key", warnings=warnings)


def _cose_member(parsed: Any) -> tuple[Mapping[Any, Any], list[str]]:
    if isinstance(parsed, Mapping) and isinstance(parsed.get("cose"), Mapping):
        return parsed["cose"], [str(name) for name in parsed if name != "cose"]
    if isinstance(parsed, Mapping):
        return parsed, []
    raise ValueError("A COSE key is a JSON object of labels to values, or {\"cose\": {...}}.")


def _label(raw: Any) -> int:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        match = _LABEL.match(raw)
        if match:
            return int(match.group(1))
    raise ValueError(f"COSE key label {raw!r} is not an integer label such as 1, \"-2\" or \"-2 (x)\".")


def _value(label: int, value: Any, parameters: Mapping[int, tuple[str, str]], kty: Any) -> Any:
    known = parameters.get(label)
    if known is None:
        if isinstance(value, int) or value is None:
            return value
        raise ValueError(
            f"COSE key label {label} is not a parameter the COSE registries define for kty {kty}; "
            "its value cannot be told apart as text or bytes, so it is not encoded."
        )
    name, cbor_type = known
    if cbor_type == "bstr / bool" and isinstance(value, bool):
        return value
    if cbor_type.startswith("bstr"):
        return _byte_string(label, name, value)
    if cbor_type == "int / tstr" and isinstance(value, (int, str)) and not isinstance(value, bool):
        return value
    if cbor_type == "[+ (int / tstr)]" and isinstance(value, list) and value and all(
        isinstance(item, (int, str)) and not isinstance(item, bool) for item in value
    ):
        return list(value)
    raise ValueError(f"COSE key {name} (label {label}) must be {cbor_type}; got {type(value).__name__}.")


def _byte_string(label: int, name: str, value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return encoding.sniff(value, allow_separators=False).data
        except encoding.EncodingError as exc:
            raise ValueError(f"COSE key {name} (label {label}) is not hex or base64url: {exc}.") from exc
    raise ValueError(f"COSE key {name} (label {label}) must be a byte string, given as hex or base64url.")
