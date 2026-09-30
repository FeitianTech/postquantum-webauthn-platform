"""JSON the decoder is given: a PublicKeyCredential, client data, or any other JSON.

A PublicKeyCredential's binary members are decoded where they sit, each one
that does not decode shown as sent with where it stops.
"""
from __future__ import annotations

import functools
import json
from collections.abc import Callable, Mapping
from typing import Any

from fido2.webauthn import CollectedClientData

from ...encoding import encode_base64url
from ...json_values import make_json_safe
from .. import values
from . import (
    ambiguous_input,
    attestation_object,
    authenticator_data_findings,
    binary_text,
    canonical,
    cbor_parser,
    ctap,
    interpretations,
    json_input,
    key_collisions,
)
from . import authenticator_data as auth_data_reader


def decode_json_object(value: Any, raw_text: str | None = None, *, lenient: bool = False) -> dict[str, Any]:
    if isinstance(value, Mapping) and is_public_key_credential(value):
        result = decode_public_key_credential(value, raw_text=raw_text, lenient=lenient)
        if is_client_data_dict(value):
            # Its members make client data too; a response member makes it a credential first.
            also = ambiguous_input.finding("a PublicKeyCredential", "client data")
            ctap._attach_findings(result, [also, *(result.get("findings") or [])])
        return result

    if isinstance(value, Mapping) and is_client_data_dict(value):
        details = build_client_data_details(value, raw_text=raw_text)
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


def decode_public_key_credential(
    credential: Mapping[str, Any], raw_text: str | None = None, *, lenient: bool = False
) -> dict[str, Any]:
    response = credential.get("response")
    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}

    decoded = _credential_fields(credential, raw_text)
    findings: list[dict[str, Any]] = []
    response_details, attestation_entry, authenticator_entry = _response_fields(response_mapping, findings, lenient)
    decoded["response"] = response_details

    format_label = "PublicKeyCredential"
    if attestation_entry:
        format_label = "PublicKeyCredential (registration)"
    elif authenticator_entry:
        format_label = "PublicKeyCredential (authentication)"

    extra, located = interpretations.for_public_key_credential(
        credential,
        _cbor_map_or_none(attestation_entry[0]) if attestation_entry else None,
        authenticator_entry[0] if authenticator_entry else None,
    )
    result = {
        "format": format_label,
        "inputEncoding": "json",
        "decoded": decoded,
        "extraData": extra,
    }
    ctap._attach_findings(result, findings + located)
    return result


def _credential_fields(credential: Mapping[str, Any], raw_text: str | None) -> dict[str, Any]:
    """The credential's own members: id, type, attachment, transports, rawId, extension results."""

    decoded: dict[str, Any] = {
        "id": credential.get("id"),
        "type": credential.get("type"),
    }

    authenticator_attachment = credential.get("authenticatorAttachment")
    if authenticator_attachment is not None:
        decoded["authenticatorAttachment"] = authenticator_attachment

    transports = credential.get("transports")
    if transports is not None:
        decoded["transports"] = transports

    raw_id_bytes = binary_text.decode_binary_field(credential.get("rawId"))
    if raw_id_bytes:
        raw_id, raw_id_encoding = raw_id_bytes
        decoded["rawId"] = {
            "raw": credential.get("rawId"),
            "binary": values.binary_summary(raw_id, raw_id_encoding),
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
    return decoded


# The response members that hold bytes; _response_fields decodes the first three too.
_RESPONSE_BINARY_FIELDS = ("attestationObject", "authenticatorData", "clientDataJSON", "signature", "userHandle")


def _response_fields(
    response_mapping: Mapping[str, Any], findings: list[dict[str, Any]], lenient: bool = False
) -> tuple[dict[str, Any], tuple[bytes, str] | None, tuple[bytes, str] | None]:
    """The response's members, each binary one decoded; and its attestation object and authenticator data."""

    response_details: dict[str, Any] = {
        key: value for key, value in response_mapping.items() if key not in _RESPONSE_BINARY_FIELDS
    }
    readers = {
        "attestationObject": _nested_attestation_object,
        "authenticatorData": _nested_authenticator_data,
        "clientDataJSON": functools.partial(_nested_client_data, lenient=lenient),
    }
    entries: dict[str, tuple[bytes, str] | None] = {}
    for name in _RESPONSE_BINARY_FIELDS:
        entry = entries[name] = binary_text.decode_binary_field(response_mapping.get(name))
        if not entry:
            continue
        field_bytes, field_encoding = entry
        response_details[name] = {
            "raw": response_mapping.get(name),
            "binary": values.binary_summary(field_bytes, field_encoding),
        }
        read = readers.get(name)
        if read is not None:
            response_details[name].update(_read_nested(f"response.{name}", field_bytes, read, findings))
    return response_details, entries["attestationObject"], entries["authenticatorData"]


def _cbor_map_or_none(data: bytes) -> tuple[Mapping[Any, Any], dict[str, Any], bytes] | None:
    """The CBOR map ``data`` holds, with its node and bytes; ``None`` if it holds no map."""

    try:
        node, _end, _ = cbor_parser.decode_item(data)
    except cbor_parser._CborDecodingError:
        return None
    value = cbor_parser._structure_to_value(node)
    return (value, node, data) if isinstance(value, Mapping) else None


def _read_nested(
    source: str,
    data: bytes,
    read: Callable[[bytes], tuple[dict[str, Any], list[dict[str, Any]]]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Decode one binary field of a PublicKeyCredential, reporting where it fails.

    A field that does not decode is shown as sent, with ``parseError`` saying
    where it stops; the rest of the credential still decodes. Each finding
    carries ``source``, and its offset counts from that field's decoded bytes.
    """

    try:
        details, nested = read(data)
    except ValueError as exc:
        offset, path, reason = _error_location(exc)
        findings.append(
            {
                "code": "parse-error",
                "category": "malformed",
                "offset": offset,
                "path": path,
                "message": f"{source} does not decode: {reason}",
                "source": source,
            }
        )
        return {"parseError": {"offset": offset, "path": path, "reason": reason}}
    findings.extend({**finding, "source": source} for finding in nested)
    return {"details": details}


def _error_location(exc: ValueError) -> tuple[int, str, str]:
    if isinstance(exc, (cbor_parser._CborDecodingError, auth_data_reader._LocatedError, json_input.JsonConstantError)):
        return exc.offset, exc.path, exc.reason
    if isinstance(exc, json.JSONDecodeError):
        return exc.pos, "$", exc.msg
    if isinstance(exc, UnicodeDecodeError):
        return exc.start, "$", f"not UTF-8 ({exc.reason})"
    return 0, "$", str(exc)


def _nested_attestation_object(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    details, node, end = attestation_object.read(data)
    findings = canonical.check(node, data) + key_collisions.check(node) + ctap._trailing_findings(data, end)
    return details, findings + authenticator_data_findings.for_member(node, data, ("authData",))


def _nested_authenticator_data(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return auth_data_reader._describe_authenticator_data_bytes(data), authenticator_data_findings.check(data, 0, "$")


def _nested_client_data(data: bytes, *, lenient: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed, findings = json_input.read_bytes(data, lenient=lenient)
    if not isinstance(parsed, dict):
        # WebAuthn L3 section 5.8.1: a JSON object. Anything else has no client data to show.
        raise ValueError(f"client data is JSON, but not an object: {json.dumps(parsed)[:40]}")
    return describe_client_data_from_bytes(data, lenient=lenient), findings


def describe_client_data_from_bytes(data: bytes, *, lenient: bool = False) -> dict[str, Any]:
    text = data.decode("utf-8")
    parsed, _repeated = json_input.read(text, lenient=lenient)
    details = build_client_data_details(parsed, raw_text=text)

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


def build_client_data_details(
    parsed: Mapping[str, Any], raw_text: str | None = None
) -> dict[str, Any]:
    details: dict[str, Any] = {}

    type_value = parsed.get("type")
    if type_value is not None:
        details["type"] = type_value

    challenge_value = parsed.get("challenge")
    if challenge_value is not None:
        challenge_info: dict[str, Any] = {"raw": challenge_value}
        if isinstance(challenge_value, str):
            try:
                challenge_bytes, challenge_encoding = binary_text.decode_binary_input(challenge_value)
            except ValueError:
                pass
            else:
                challenge_info.update(values.binary_summary(challenge_bytes, challenge_encoding))
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


def is_public_key_credential(value: Mapping[str, Any]) -> bool:
    response = value.get("response")
    if not isinstance(response, Mapping):
        return False

    if not value.get("type") and not value.get("id"):
        return False

    return any(
        field in response
        for field in ("attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle")
    )


def is_client_data_dict(value: Mapping[str, Any]) -> bool:
    if not isinstance(value.get("type"), str):
        return False
    if "challenge" not in value:
        return False
    return isinstance(value.get("origin"), str)
