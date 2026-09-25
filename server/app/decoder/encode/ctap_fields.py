"""CTAP field lookup/coercion helpers and nested structure encoders."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ..decode.keys import read_json_key, typed_key_kind
from .binary_decode import (
    _maybe_decode_bytes,
    _require_bytes,
    _require_certificate_bytes,
)
from .binary_extract import _restore_generic_structure
from .constants import _CTAP_FIELD_LABELS, _CTAP_LABELED_KEY_PATTERN
from .typed_keys import add_key


def _reject_typed_keys(structure: Mapping[Any, Any], kind: str) -> None:
    """Refuse a typed key spelling at member level: ``"fmt" (text)`` is a text key, not member 1.

    CTAP numbers its members with integer keys; the decoder shows any other key
    of a CTAP map with its type. Its value's JSON cannot say whether a string was
    bytes or text, so it is not passed through either.
    """

    for key in structure:
        named = typed_key_kind(key)
        if named is not None:
            raise ValueError(
                f"{kind} key {key!r} is a {named} key, not a CTAP member (CTAP numbers its members with "
                "integers). The encoder does not guess its value's type: encode this map from its EDN."
            )


def _reject_misnamed_request_fields(
    structure: Mapping[Any, Any],
    kind: str,
    *,
    bare_names: bool = True,
) -> None:
    """Refuse a request field that CTAP 2.2 does not call by the name it carries.

    An authenticator is sent the number, never the name. "8 (largeBlobKey)" in a
    getAssertion request names a parameter CTAP does not define, and
    "11 (largeBlobKey)" in a makeCredential request names something other than
    attestationFormatsPreference; encoding either would hand the authenticator a
    field its author did not mean. A bare number is a raw field the author asked
    for on purpose and is left alone.
    """

    _reject_typed_keys(structure, kind)
    members = _CTAP_FIELD_LABELS[kind]
    command = kind.removesuffix("Request")
    known_names = {name.lower() for name in members.values()}
    for key in structure:
        if not isinstance(key, str):
            continue
        text = key.strip()
        match = _CTAP_LABELED_KEY_PATTERN.match(text)
        if match:
            number = int(match.group(1))
            name = match.group(2).strip()
            expected = members.get(number)
            if expected is None:
                raise ValueError(f"CTAP 2.2 {command} has no parameter 0x{number:02x} ({name}).")
            if name.lower() != expected.lower():
                raise ValueError(f"CTAP 2.2 {command} parameter 0x{number:02x} is {expected}, not {name}.")
        elif bare_names and not _is_bare_number(text) and text.lower() not in known_names:
            raise ValueError(f"CTAP 2.2 {command} has no parameter named {text}.")


def _reject_unknown_members(structure: Mapping[Any, Any], kind: str) -> None:
    """Refuse what a builder for ``kind`` would otherwise drop without a word.

    A member CTAP 2.2 does not define for ``kind`` is not passed through either:
    the decoder shows byte strings as hex text, so from JSON alone "abcd" could
    have been a byte string or a text string, and encoding it would be a guess.
    Two keys that name one member ("1" and "1 (fmt)") are refused too, since
    only one of them could be encoded.
    """

    _reject_typed_keys(structure, kind)
    members = _CTAP_FIELD_LABELS[kind]
    claimed: dict[int, Any] = {}
    unknown: list[str] = []
    for key in structure:
        number = next(
            (
                number
                for number, label in members.items()
                if _ctap_key_matches(key, {label.lower(), str(number), f"{number} ({label})"})
            ),
            None,
        )
        if number is None:
            unknown.append(repr(key))
        elif number in claimed:
            raise ValueError(
                f"{kind} member {number} ({members[number]}) is given twice, as {claimed[number]!r} and {key!r}."
            )
        elif structure[key] is None:
            # The builders read a null member as absent: encoding would drop it.
            raise ValueError(
                f"{kind} member {number} ({members[number]}) is null. CTAP defines no null member, and "
                "the encoder does not drop one: encode this map from its EDN."
            )
        else:
            claimed[number] = key
    if unknown:
        raise ValueError(
            f"{kind} has no member {', '.join(unknown)} in CTAP 2.2. The encoder does not drop it, and "
            "cannot pass it through: its JSON does not say whether a string was a byte or text string."
        )


def _is_bare_number(text: str) -> bool:
    lowered = text.lower()
    if lowered.startswith("0x"):
        return all(char in "0123456789abcdef" for char in lowered[2:]) and len(lowered) > 2
    return lowered.isdigit()


def _get_ctap_member(structure: Mapping[str, Any], kind: str, number: int) -> Any:
    """Look up member ``number`` of a ``kind`` map under the name the CTAP table gives it."""

    return _get_ctap_field_value(structure, _CTAP_FIELD_LABELS[kind][number], number)


def _get_ctap_field_value(
    structure: Mapping[str, Any],
    label: str,
    index: int | None = None,
) -> Any:
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
    normalized_lower = {candidate.strip().lower() for candidate in candidates}

    if isinstance(key, str):
        match = _CTAP_LABELED_KEY_PATTERN.match(key)
        if match:
            # "N (label)" names its field twice. It is that field only when both
            # agree: "1 (rpId)" is not a makeCredential response's "1 (fmt)".
            number = int(match.group(1))
            label = match.group(2).strip().lower()
            numbers = {
                int(candidate) for candidate in normalized_lower if candidate.lstrip("-").isdigit()
            }
            return label in normalized_lower and (not numbers or number in numbers)

    return key_lower in normalized_lower


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

    statement: dict[Any, Any] = {}
    spelled: dict[Any, Any] = {}
    for label, entry in value.items():
        key = read_json_key(label) if isinstance(label, str) else label
        add_key(statement, spelled, key, label, "attStmt")
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
            statement[key] = (
                decoded if decoded is not None else _restore_generic_structure(entry)
            )
    return statement


def _encode_ctap_user(value: Any) -> dict[str, Any]:
    mapping = _require_mapping(value, "user")
    result: dict[str, Any] = {}

    if "id" in mapping:
        result["id"] = _require_bytes(mapping["id"], "user.id")
    if "name" in mapping:
        result["name"] = _ensure_text(mapping["name"], "user.name")
    if "displayName" in mapping:
        result["displayName"] = _ensure_text(mapping["displayName"], "user.displayName")
    if "icon" in mapping and mapping["icon"] is not None:
        result["icon"] = _ensure_text(str(mapping["icon"]), "user.icon")

    spelled: dict[Any, Any] = {}
    for label in ("id", "name", "displayName", "icon"):
        if label in mapping:
            add_key(result, spelled, label, label, "user")
    for label, entry in mapping.items():
        if label in {"id", "name", "displayName", "icon"}:
            continue
        key = read_json_key(label) if isinstance(label, str) else label
        add_key(result, spelled, key, label, "user")
        decoded = _maybe_decode_bytes(entry)
        result[key] = decoded if decoded is not None else _restore_generic_structure(entry)

    return result


def _encode_allow_list(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_encode_credential_descriptor(item) for item in value]
    raise ValueError("allowList must be an array of credential descriptors.")


def _encode_credential_descriptor(value: Any) -> Any:
    decoded = _maybe_decode_bytes(value)
    if decoded is not None:
        return decoded

    mapping = _require_mapping(value, "credential descriptor")
    descriptor: dict[str, Any] = {}

    if "type" in mapping:
        descriptor["type"] = _ensure_text(mapping["type"], "credential.type")
    if "id" in mapping:
        descriptor["id"] = _require_bytes(mapping["id"], "credential.id")
    if "transports" in mapping:
        descriptor["transports"] = _restore_generic_structure(mapping["transports"])

    spelled: dict[Any, Any] = {}
    for label in ("type", "id", "transports"):
        if label in mapping:
            add_key(descriptor, spelled, label, label, "credential descriptor")
    for label, entry in mapping.items():
        if label in {"type", "id", "transports"}:
            continue
        key = read_json_key(label) if isinstance(label, str) else label
        add_key(descriptor, spelled, key, label, "credential descriptor")
        decoded_entry = _maybe_decode_bytes(entry)
        descriptor[key] = (
            decoded_entry
            if decoded_entry is not None
            else _restore_generic_structure(entry)
        )

    return descriptor
