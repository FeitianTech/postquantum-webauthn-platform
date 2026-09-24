"""Top-level decode pipeline helpers."""
from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography import x509

from fido2.utils import ByteBuffer
from fido2.webauthn import AuthenticatorData, CollectedClientData

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
    summarize_authenticator_extensions,
)
from . import canonical, cbor_parser, ctap, response

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

    format_label = "PublicKeyCredential"
    if attestation_entry:
        format_label = "PublicKeyCredential (registration)"
        att_bytes, att_encoding = attestation_entry
        response_details["attestationObject"] = {
            "raw": response_mapping.get("attestationObject"),
            "binary": _binary_summary(att_bytes, att_encoding),
            "details": _parse_attestation_object(att_bytes),
        }

    if authenticator_entry:
        if format_label == "PublicKeyCredential":
            format_label = "PublicKeyCredential (authentication)"
        auth_bytes, auth_encoding = authenticator_entry
        response_details["authenticatorData"] = {
            "raw": response_mapping.get("authenticatorData"),
            "binary": _binary_summary(auth_bytes, auth_encoding),
            "details": _describe_authenticator_data_bytes(auth_bytes),
        }

    client_data_entry = _decode_binary_field(response_mapping.get("clientDataJSON"))
    if client_data_entry:
        client_bytes, client_encoding = client_data_entry
        response_details["clientDataJSON"] = {
            "raw": response_mapping.get("clientDataJSON"),
            "binary": _binary_summary(client_bytes, client_encoding),
            "details": _describe_client_data_from_bytes(client_bytes),
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

    return {
        "format": format_label,
        "inputEncoding": "json",
        "decoded": decoded,
    }


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
    return result.data, result.encoding


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

    result: dict[str, Any] = {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
    }
    ctap._attach_findings(result, canonical.check(node, data) + ctap._trailing_findings(data, end))
    return result


def _try_decode_authenticator_data(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details = _describe_authenticator_data_bytes(data)
    except Exception:
        return None

    return {
        "format": "Authenticator data (binary)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
    }


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
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    parsed_json = None if _is_lone_ctap_byte_hex(trimmed) else _try_parse_json(trimmed)
    if parsed_json is not None:
        result = _decode_json_object(parsed_json, raw_text=trimmed)
    elif _looks_like_pem(trimmed):
        result = _decode_pem_certificates(trimmed)
    else:
        data, encoding = _decode_binary_input(trimmed)
        result = _decode_binary_payload(data, encoding, lenient=lenient)

    return response._prepare_decoder_response(result)


def _is_lone_ctap_byte_hex(text: str) -> bool:
    # "31" is valid JSON, but as the whole input to this decoder it is the byte
    # 0x31, PIN_INVALID: a two-digit JSON number would tell nobody anything.
    if len(text) != 2:
        return False
    try:
        data = bytes.fromhex(text)
    except ValueError:
        return False
    return ctap._extract_ctap_prefix(data)[0] is not None


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


def _read_authenticator_data(data: bytes) -> dict[str, Any]:
    """Split authenticator data into its fields, or raise ``ValueError``.

    Accepts exactly what fido2's ``AuthenticatorData`` accepts -- a 37-byte
    header, the attested credential data its AT flag announces, the extensions
    its ED flag announces, and nothing after them -- but reads the credential
    public key and the extensions with the decoder's own strict CBOR parser.
    """

    if len(data) < 37:
        raise ValueError("Authenticator data is shorter than its 37-byte header.")
    flags = data[32]
    fields: dict[str, Any] = {
        "rpIdHash": data[:32],
        "flags": flags,
        "counter": int.from_bytes(data[33:37], "big"),
    }
    offset = 37

    if flags & AuthenticatorData.FLAG.AT:
        if len(data) - offset < 18:
            raise ValueError("Attested credential data is truncated.")
        aaguid = data[offset : offset + 16]
        id_length = int.from_bytes(data[offset + 16 : offset + 18], "big")
        offset += 18
        if offset + id_length > len(data):
            raise ValueError("The credential ID is truncated.")
        credential_id = data[offset : offset + id_length]
        node, offset, _ = cbor_parser.decode_item(data, offset + id_length)
        public_key = cbor_parser._structure_to_value(node)
        if not isinstance(public_key, Mapping):
            raise ValueError("The credential public key is not a COSE_Key map.")
        fields["attestedCredentialData"] = (aaguid, credential_id, public_key)

    if flags & AuthenticatorData.FLAG.ED:
        node, offset, _ = cbor_parser.decode_item(data, offset)
        fields["extensions"] = cbor_parser._structure_to_value(node)

    if offset != len(data):
        raise ValueError("Wrong length")
    return fields


def _describe_authenticator_data_bytes(data: bytes) -> dict[str, Any]:
    fields = _read_authenticator_data(data)
    flags = fields["flags"]

    flag_details = {
        "value": flags,
        "bitfield": f"0b{flags:08b}",
        "userPresent": bool(flags & AuthenticatorData.FLAG.UP),
        "userVerified": bool(flags & AuthenticatorData.FLAG.UV),
        "backupEligibility": bool(flags & AuthenticatorData.FLAG.BE),
        "backupState": bool(flags & AuthenticatorData.FLAG.BS),
        "attestedCredentialDataIncluded": bool(flags & AuthenticatorData.FLAG.AT),
        "extensionDataIncluded": bool(flags & AuthenticatorData.FLAG.ED),
        "flagsSet": [flag.name for flag in AuthenticatorData.FLAG if flags & flag],
    }

    details: dict[str, Any] = {
        "rpIdHash": {
            "hex": fields["rpIdHash"].hex(),
            "base64url": encode_base64url(fields["rpIdHash"]),
        },
        "flags": flag_details,
        "signCount": fields["counter"],
    }

    credential_data = fields.get("attestedCredentialData")
    if credential_data is not None:
        aaguid, credential_id, public_key = credential_data
        details["attestedCredentialData"] = {
            "aaguid": str(uuid.UUID(bytes=aaguid)),
            "aaguidHex": aaguid.hex(),
            "credentialId": _binary_summary(credential_id, "binary"),
            "publicKey": make_json_safe(dict(public_key)),
        }

    if "extensions" in fields:
        extensions = fields["extensions"]
        extensions_payload: dict[str, Any] = {
            "raw": make_json_safe(extensions),
        }
        if isinstance(extensions, Mapping):
            extensions_payload["summary"] = make_json_safe(
                summarize_authenticator_extensions(extensions)
            )
        details["extensions"] = extensions_payload

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
    if not isinstance(fmt, str) or not isinstance(auth_data, bytes) or not isinstance(att_stmt, Mapping):
        raise ValueError("An attestation object has a text fmt, byte string authData and map attStmt.")

    details: dict[str, Any] = {
        "attestationFormat": fmt,
        "attestationStatement": make_json_safe(att_stmt),
        "authenticatorData": _describe_authenticator_data_bytes(auth_data),
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
