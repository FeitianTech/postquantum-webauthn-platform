"""Top-level decode pipeline helpers."""
from __future__ import annotations

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
    key_collisions,
    response,
)
from .authenticator_data import _describe_authenticator_data_bytes, _LocatedError

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def _decode_json_object(value: Any, raw_text: str | None = None) -> dict[str, Any]:
    if isinstance(value, Mapping) and _is_public_key_credential(value):
        return _decode_public_key_credential(value, raw_text=raw_text)

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
    credential: Mapping[str, Any], raw_text: str | None = None
) -> dict[str, Any]:
    response = credential.get("response")
    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}

    response_details: dict[str, Any] = {
        key: value
        for key, value in response_mapping.items()
        if key
        not in {"attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle"}
    }

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

    attestation_entry = _decode_binary_field(response_mapping.get("attestationObject"))
    authenticator_entry = _decode_binary_field(response_mapping.get("authenticatorData"))
    findings: list[dict[str, Any]] = []

    format_label = "PublicKeyCredential"
    if attestation_entry:
        format_label = "PublicKeyCredential (registration)"
        att_bytes, att_encoding = attestation_entry
        response_details["attestationObject"] = {
            "raw": response_mapping.get("attestationObject"),
            "binary": _binary_summary(att_bytes, att_encoding),
            **_read_nested("response.attestationObject", att_bytes, _nested_attestation_object, findings),
        }

    if authenticator_entry:
        if format_label == "PublicKeyCredential":
            format_label = "PublicKeyCredential (authentication)"
        auth_bytes, auth_encoding = authenticator_entry
        response_details["authenticatorData"] = {
            "raw": response_mapping.get("authenticatorData"),
            "binary": _binary_summary(auth_bytes, auth_encoding),
            **_read_nested("response.authenticatorData", auth_bytes, _nested_authenticator_data, findings),
        }

    client_data_entry = _decode_binary_field(response_mapping.get("clientDataJSON"))
    if client_data_entry:
        client_bytes, client_encoding = client_data_entry
        response_details["clientDataJSON"] = {
            "raw": response_mapping.get("clientDataJSON"),
            "binary": _binary_summary(client_bytes, client_encoding),
            **_read_nested("response.clientDataJSON", client_bytes, _nested_client_data, findings),
        }

    signature_entry = _decode_binary_field(response_mapping.get("signature"))
    if signature_entry:
        sig_bytes, sig_encoding = signature_entry
        response_details["signature"] = {
            "raw": response_mapping.get("signature"),
            "binary": _binary_summary(sig_bytes, sig_encoding),
        }

    user_handle_entry = _decode_binary_field(response_mapping.get("userHandle"))
    if user_handle_entry:
        handle_bytes, handle_encoding = user_handle_entry
        response_details["userHandle"] = {
            "raw": response_mapping.get("userHandle"),
            "binary": _binary_summary(handle_bytes, handle_encoding),
        }

    decoded["response"] = response_details

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
    if isinstance(exc, (cbor_parser._CborDecodingError, _LocatedError)):
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


def _nested_client_data(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _describe_client_data_from_bytes(data), []


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
    # A single byte CTAP names is a status or command byte. Read as text it is
    # at most an ASCII digit, which would otherwise be shown as a JSON number:
    # 0x31 (PIN_INVALID) as 1.
    if len(data) == 1 and ctap._extract_ctap_prefix(data)[0] is not None:
        return ctap._try_decode_cbor(data, encoding, lenient=lenient)

    text_version = _try_decode_utf8(data)

    if text_version and _looks_like_pem(text_version):
        result = _decode_pem_certificates(text_version)
        result["inputEncoding"] = encoding
        result["binary"] = _binary_summary(data, encoding)
        return result

    if text_version:
        json_obj = _try_parse_json(text_version)
        if json_obj is not None:
            if isinstance(json_obj, Mapping) and _is_client_data_dict(json_obj):
                details = _describe_client_data_from_bytes(data)
                return {
                    "format": "WebAuthn client data (binary)",
                    "inputEncoding": encoding,
                    "decoded": details,
                    "binary": _binary_summary(data, encoding),
                }
            return {
                "format": "JSON (binary)",
                "inputEncoding": encoding,
                "decoded": json_obj,
                "binary": _binary_summary(data, encoding),
            }

    certificate_result = _try_decode_certificate_bytes(data, encoding)
    if certificate_result is not None:
        return certificate_result

    attestation_result = _try_decode_attestation_object(data, encoding)
    if attestation_result is not None:
        return attestation_result

    authenticator_result = _try_decode_authenticator_data(data, encoding)
    if authenticator_result is not None:
        return authenticator_result

    # Whatever is left is read as CBOR, strictly: input that is not
    # well-formed CBOR fails here, with the offset where it goes wrong. Only a
    # request for lenient decoding reads past that, and it lists what it skipped.
    return ctap._try_decode_cbor(data, encoding, lenient=lenient)


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
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


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


def _try_parse_json(value: str) -> Any | None:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
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
    lists each item it kept partially or stepped over.

    Text that is both hexadecimal and a JSON number is read by the precedence
    in ``ambiguous_input``, and the response names the reading not taken.
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    parsed_json = _try_parse_json(trimmed)
    ambiguity = ambiguous_input.check(trimmed, parsed_json)
    if ambiguity is not None and ambiguity["readAs"] == "hex":
        parsed_json = None
    if parsed_json is not None:
        result = _decode_json_object(parsed_json, raw_text=trimmed)
    elif _looks_like_pem(trimmed):
        result = _decode_pem_certificates(trimmed)
    else:
        data, encoding = _decode_binary_input(trimmed)
        result = _decode_binary_payload(data, encoding, lenient=lenient)

    if ambiguity is not None:
        ctap._attach_findings(result, [ambiguity, *(result.get("findings") or [])])
    return response._prepare_decoder_response(result)


def _describe_client_data_from_bytes(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8")
    parsed = json.loads(text)
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
