"""Top-level decode pipeline helpers."""
from __future__ import annotations

import functools
import json
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from cryptography import x509

from fido2.utils import ByteBuffer
from fido2.webauthn import CollectedClientData

from ...encoding import (
    EncodingError,
    SniffResult,
    encode_base64,
    sniff,
    try_decode_base64,
    try_decode_base64url,
)
from ...webauthn.attestation import (
    colon_hex,
    encode_base64url,
    make_json_safe,
    serialize_attestation_certificate,
)
from . import (
    ambiguous_input,
    authenticator_data_findings,
    canonical,
    cbor_parser,
    ctap,
    interpretations,
    json_input,
    key_collisions,
    readings,
    response,
)
from .authenticator_data import _describe_authenticator_data_bytes, _LocatedError
from .json_input import read_or_none as _read_json

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def _decode_json_object(value: Any, raw_text: str | None = None, *, lenient: bool = False) -> dict[str, Any]:
    if isinstance(value, Mapping) and _is_public_key_credential(value):
        result = _decode_public_key_credential(value, raw_text=raw_text, lenient=lenient)
        if _is_client_data_dict(value):
            # Its members make client data too; a response member makes it a credential first.
            also = ambiguous_input.finding("a PublicKeyCredential", "client data")
            ctap._attach_findings(result, [also, *(result.get("findings") or [])])
        return result

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
        entry = entries[name] = _decode_binary_field(response_mapping.get(name))
        if not entry:
            continue
        field_bytes, field_encoding = entry
        response_details[name] = {
            "raw": response_mapping.get(name),
            "binary": _binary_summary(field_bytes, field_encoding),
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
    if isinstance(exc, (cbor_parser._CborDecodingError, _LocatedError, json_input.JsonConstantError)):
        return exc.offset, exc.path, exc.reason
    if isinstance(exc, json.JSONDecodeError):
        return exc.pos, "$", exc.msg
    if isinstance(exc, UnicodeDecodeError):
        return exc.start, "$", f"not UTF-8 ({exc.reason})"
    return 0, "$", str(exc)


def _nested_attestation_object(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    details, node, end = _read_attestation_object(data)
    findings = canonical.check(node, data) + key_collisions.check(node) + ctap._trailing_findings(data, end)
    return details, findings + authenticator_data_findings.for_member(node, data, ("authData",))


def _nested_authenticator_data(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _describe_authenticator_data_bytes(data), authenticator_data_findings.check(data, 0, "$")


def _nested_client_data(data: bytes, *, lenient: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed, findings = json_input.read_bytes(data, lenient=lenient)
    if not isinstance(parsed, dict):
        # WebAuthn L3 section 5.8.1: a JSON object. Anything else has no client data to show.
        raise ValueError(f"client data is JSON, but not an object: {json.dumps(parsed)[:40]}")
    return _describe_client_data_from_bytes(data, lenient=lenient), findings


def _decode_pem_certificates(text: str) -> dict[str, Any]:
    certificates = []
    for match in _PEM_CERT_PATTERN.finditer(text):
        cert_bytes = try_decode_base64(match.group("body"))
        if cert_bytes is None:
            continue
        certificates.append(cert_bytes)

    if not certificates:
        raise ValueError("No PEM certificate data found.")

    decoded_details = [
        serialize_attestation_certificate(cert_bytes) for cert_bytes in certificates
    ]

    payload: dict[str, Any]
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


def _decode_binary_payload(data: bytes, encoding: str, *, lenient: bool = False) -> dict[str, Any]:
    # The readings, in order, are decode/readings.py's.
    return readings.read_binary(data, encoding, lenient=lenient)


def _sniff_binary_input(value: str) -> SniffResult:
    """Decode decoder input and report which encoding actually matched.

    The label comes from the decoder that succeeded, not from scanning the
    input for ``-``/``_``: a base64url payload that happens to use none of
    those characters is byte-identical to the same text read as standard
    base64, and :attr:`~server.app.encoding.SniffResult.ambiguous` says so
    instead of the pipeline picking one and asserting it.
    """

    if not "".join(value.split()):
        raise ValueError("No binary data present.")

    try:
        return sniff(value)
    except EncodingError as exc:
        digits = _odd_hex_digits(value)
        if digits:
            raise ValueError(
                f"Input is {digits} hexadecimal digits, an odd number, so no bytes; and it is not base64 either."
            ) from exc
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


_HEX_TEXT = re.compile(r"(?:0[xX])?[0-9A-Fa-f:]+")


def _odd_hex_digits(value: str) -> int:
    """How many hexadecimal digits ``value`` is, when it is an odd number of them; else 0."""

    text = "".join(value.split())
    digits = len(text.removeprefix("0x").removeprefix("0X").replace(":", ""))
    return digits if _HEX_TEXT.fullmatch(text) and digits % 2 else 0


class _ReadAsBase64Error(ValueError):
    """Odd-length hexadecimal digits read as base64, whose bytes then did not decode."""

    def __init__(self, exc: ValueError, digits: int) -> None:
        for field in ("offset", "path"):
            if hasattr(exc, field):
                setattr(self, field, getattr(exc, field))
        super().__init__(f"{exc} (the input was read as base64: as hexadecimal, its {digits} digits are an odd number)")


def _decode_binary_input(value: str) -> tuple[bytes, str]:
    result = _sniff_binary_input(value)
    # Text in the alphabet base64 and base64url share decodes to the same bytes
    # in either: the label says both rather than asserting one.
    return result.data, "base64 or base64url" if result.ambiguous else result.encoding


def _decode_binary_field(value: Any) -> tuple[bytes, str] | None:
    if isinstance(value, str):
        try:
            return _decode_binary_input(value)
        except ValueError:
            return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), "binary"
    return None


def _looks_like_pem(value: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in value.upper()


def _try_decode_certificate_bytes(data: bytes, encoding: str) -> dict[str, Any] | None:
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


def _try_decode_attestation_object(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details, node, end = _read_attestation_object(data)
    except Exception:
        return None

    extra, located = interpretations.for_attestation_object(cbor_parser._structure_to_value(node), node, data)
    result: dict[str, Any] = {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
        "extraData": extra,
    }
    structure = canonical.check(node, data) + key_collisions.check(node)
    ctap._attach_findings(result, structure + ctap._trailing_findings(data, end) + located)
    return result


def _try_decode_authenticator_data(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details = _describe_authenticator_data_bytes(data)
    except Exception:
        return None

    extra, located = interpretations.for_authenticator_data(data)
    result = {
        "format": "Authenticator data (binary)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
        "extraData": extra,
    }
    ctap._attach_findings(result, located)
    return result


def _expand_cbor_value(value: Any) -> Any:
    if isinstance(value, ByteBuffer):
        return _binary_summary(value.getvalue())
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _binary_summary(bytes(value))
    if isinstance(value, Mapping):
        expanded: dict[str, Any] = {}
        for key, entry in value.items():
            expanded[str(key)] = _expand_cbor_value(entry)
        return expanded
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_expand_cbor_value(item) for item in value]
    return make_json_safe(value)


def decode_payload_text(value: str, *, lenient: bool = False) -> dict[str, Any]:
    """Decode ``value`` into a structured representation.

    CBOR is parsed strictly. ``lenient`` asks for a best-effort parse of CBOR
    that is not well-formed; the response then says so (``decodeMode``) and
    lists each item it kept partially or stepped over. JSON is RFC 8259's: text
    holding NaN or Infinity is refused with its offset, unless ``lenient`` (see
    ``json_input``).

    Text that is both hexadecimal and a JSON number is read by the precedence
    in ``ambiguous_input``, and the response names the reading not taken.
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    # Offsets count from the input as sent, blank space before it included.
    parsed_json, json_findings = _read_json(trimmed, lenient=lenient, base=len(value) - len(value.lstrip()))
    ambiguity = ambiguous_input.check(trimmed, parsed_json)
    if ambiguity is not None and ambiguity["readAs"] == "hex":
        parsed_json, json_findings = json_input.NOT_JSON, []
    if parsed_json is not json_input.NOT_JSON:
        result, taken = _decode_json_object(parsed_json, raw_text=trimmed, lenient=lenient), "json"
    elif _looks_like_pem(trimmed):
        result, taken = _decode_pem_certificates(trimmed), "pem"
    else:
        data, encoding = _decode_binary_input(trimmed)
        taken = "hex" if encoding == "hex" else "base64"
        try:
            result = _decode_binary_payload(data, encoding, lenient=lenient)
        except ValueError as exc:
            digits = _odd_hex_digits(trimmed) if encoding != "hex" else 0
            if not digits:
                raise
            raise _ReadAsBase64Error(exc, digits) from exc

    noted = ([ambiguity] if ambiguity is not None else []) + _other_text_readings(trimmed, taken) + json_findings
    if noted:
        ctap._attach_findings(result, [*noted, *(result.get("findings") or [])])
    # JSON is read leniently too, not only CBOR: the answer says how it was read.
    result.setdefault("decodeMode", "lenient" if lenient else "strict")
    return response._prepare_decoder_response(result)


def _other_text_readings(text: str, taken: str) -> list[dict[str, Any]]:
    """The later text readings that read ``text`` whole: PEM inside JSON, and base64 some reading reads whole.

    The text's order is JSON, PEM, hexadecimal, base64; JSON digits that are also
    hexadecimal have ``ambiguous_input.check``'s finding.
    """

    found: list[dict[str, Any]] = []
    if taken == "json" and _looks_like_pem(text):
        try:
            _decode_pem_certificates(text)
        except ValueError:
            pass
        else:
            found.append(ambiguous_input.finding("json", "pem"))
    if taken != "base64":
        data = try_decode_base64url(text) or try_decode_base64(text)
        whole = readings.reads_whole(data) if data else []
        if whole:
            found.append(ambiguous_input.finding(taken, "base64", f" ({len(data)} bytes, read whole as {whole[0]})"))
    return found


def _describe_client_data_from_bytes(data: bytes, *, lenient: bool = False) -> dict[str, Any]:
    text = data.decode("utf-8")
    parsed, _repeated = json_input.read(text, lenient=lenient)
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


def _read_attestation_object(data: bytes) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Read a WebAuthn attestation object: its details, its CBOR node, where it ends.

    It is a CBOR map with a text ``fmt``, a byte string ``authData`` holding
    valid authenticator data, and a map ``attStmt``; anything else raises.
    """

    node, end, _ = cbor_parser.decode_item(data)
    value = cbor_parser._structure_to_value(node)
    if not isinstance(value, Mapping):
        raise ValueError("An attestation object is a CBOR map.")
    fmt, auth_data, att_stmt = value.get("fmt"), value.get("authData"), value.get("attStmt")
    # WebAuthn L3 section 8.9: a compound statement's attStmt is an array.
    statement = isinstance(att_stmt, Mapping) or (fmt == "compound" and isinstance(att_stmt, list))
    if not isinstance(fmt, str) or not isinstance(auth_data, bytes) or not statement:
        raise ValueError(
            "An attestation object has a text fmt, byte string authData and map attStmt (an array for compound)."
        )

    try:
        authenticator_data = _describe_authenticator_data_bytes(auth_data)
    except (cbor_parser._CborDecodingError, _LocatedError) as exc:
        member = authenticator_data_findings.member_node(node, ("authData",))
        start = member["end"] - member["length"] if member and not member.get("indefinite") else 0
        path = member["path"] if member else "$"
        raise type(exc)(exc.reason, start + exc.offset, path + exc.path[1:]) from exc
    details: dict[str, Any] = {
        "attestationFormat": fmt,
        "attestationStatement": make_json_safe(att_stmt),
        "authenticatorData": authenticator_data,
        "cbor": make_json_safe(value),
    }

    certificate_details = _extract_attestation_certificate(att_stmt)
    if certificate_details is not None:
        details["attestationCertificate"] = certificate_details

    return details, node, end


def _parse_attestation_object(data: bytes) -> dict[str, Any]:
    details, _node, end = _read_attestation_object(data)
    if end != len(data):
        raise ValueError("Extraneous data after the attestation object.")
    return details


def _extract_attestation_certificate(att_stmt: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(att_stmt, Mapping):
        return None

    chain = att_stmt.get("x5c")
    if not isinstance(chain, Sequence) or not chain:
        return None

    first_entry = chain[0]
    cert_bytes: bytes | None

    if isinstance(first_entry, str):
        cert_bytes = try_decode_base64(first_entry)
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


def _binary_summary(data: bytes, encoding: str | None = None) -> dict[str, Any]:
    summary = {
        "length": len(data),
        "base64": encode_base64(data),
        "base64url": encode_base64url(data),
        "hex": data.hex(),
        "colonHex": colon_hex(data),
    }
    if encoding:
        summary["encoding"] = encoding
    return summary


def _try_decode_utf8(data: bytes) -> str | None:
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
