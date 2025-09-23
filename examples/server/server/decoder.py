"""Utilities for decoding WebAuthn-related payloads for the demo decoder."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import string
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fido2 import cbor
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData

from .attestation import (
    colon_hex,
    encode_base64url,
    format_hex_bytes_lines,
    format_hex_string_lines,
    make_json_safe,
    serialize_attestation_certificate,
    summarize_authenticator_extensions,
)

__all__ = ["decode_payload_text"]

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def decode_payload_text(value: str) -> Dict[str, Any]:
    """Decode ``value`` into a structured representation."""

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    parsed_json = _try_parse_json(trimmed)
    if parsed_json is not None:
        result = _decode_json_object(parsed_json, raw_text=trimmed)
    elif _looks_like_pem(trimmed):
        result = _decode_pem_certificates(trimmed)
    else:
        data, encoding = _decode_binary_input(trimmed)
        result = _decode_binary_payload(data, encoding)

    return _prepare_decoder_response(result)


def _decode_json_object(value: Any, raw_text: Optional[str] = None) -> Dict[str, Any]:
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
    credential: Mapping[str, Any], raw_text: Optional[str] = None
) -> Dict[str, Any]:
    response = credential.get("response")
    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}

    response_details: Dict[str, Any] = {
        key: value
        for key, value in response_mapping.items()
        if key
        not in {"attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle"}
    }

    decoded: Dict[str, Any] = {
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


def _decode_pem_certificates(text: str) -> Dict[str, Any]:
    certificates = []
    for match in _PEM_CERT_PATTERN.finditer(text):
        body = re.sub(r"[^A-Za-z0-9+/=]", "", match.group("body"))
        if not body:
            continue
        try:
            cert_bytes = base64.b64decode(body)
        except (ValueError, binascii.Error):
            continue
        certificates.append(cert_bytes)

    if not certificates:
        raise ValueError("No PEM certificate data found.")

    decoded_details = [
        serialize_attestation_certificate(cert_bytes) for cert_bytes in certificates
    ]

    payload: Dict[str, Any]
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


def _decode_binary_payload(data: bytes, encoding: str) -> Dict[str, Any]:
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

    cbor_result = _try_decode_cbor(data, encoding)
    if cbor_result is not None:
        return cbor_result

    return {
        "format": "Binary data",
        "inputEncoding": encoding,
        "decoded": _binary_summary(data, encoding),
    }


def _decode_binary_input(value: str) -> Tuple[bytes, str]:
    cleaned = "".join(value.split())
    if not cleaned:
        raise ValueError("No binary data present.")

    hex_candidate = re.sub(r"0x", "", cleaned, flags=re.IGNORECASE).replace(":", "")
    if hex_candidate and all(char in string.hexdigits for char in hex_candidate):
        if len(hex_candidate) % 2:
            hex_candidate = "0" + hex_candidate
        return bytes.fromhex(hex_candidate), "hex"

    has_url_chars = any(char in "-_" for char in cleaned)
    base64_candidate = cleaned.replace("-", "+").replace("_", "/")
    padding = (-len(base64_candidate)) % 4
    if padding:
        base64_candidate += "=" * padding
    try:
        decoded = base64.b64decode(base64_candidate, validate=True)
        return decoded, "base64url" if has_url_chars else "base64"
    except (ValueError, binascii.Error):
        pass

    padding = (-len(cleaned)) % 4
    try:
        decoded = base64.urlsafe_b64decode(cleaned + "=" * padding)
        return decoded, "base64url"
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


def _decode_binary_field(value: Any) -> Optional[Tuple[bytes, str]]:
    if isinstance(value, str):
        try:
            return _decode_binary_input(value)
        except ValueError:
            return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), "binary"
    return None


def _try_parse_json(value: str) -> Optional[Any]:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _looks_like_pem(value: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in value.upper()


def _try_decode_certificate_bytes(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
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


def _try_decode_attestation_object(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    try:
        details = _parse_attestation_object(data)
    except Exception:
        return None

    return {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": _binary_summary(data, encoding),
    }


def _try_decode_authenticator_data(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
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


def _try_decode_cbor(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    try:
        decoded = cbor.decode(data)
    except Exception:
        return None

    return {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": make_json_safe(decoded),
        "binary": _binary_summary(data, encoding),
    }


def _describe_client_data_from_bytes(data: bytes) -> Dict[str, Any]:
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


def _describe_authenticator_data_bytes(data: bytes) -> Dict[str, Any]:
    auth_data = AuthenticatorData(data)
    flags = auth_data.flags

    flag_details = {
        "value": int(flags),
        "bitfield": f"0b{int(flags):08b}",
        "userPresent": bool(flags & AuthenticatorData.FLAG.UP),
        "userVerified": bool(flags & AuthenticatorData.FLAG.UV),
        "backupEligibility": bool(flags & AuthenticatorData.FLAG.BE),
        "backupState": bool(flags & AuthenticatorData.FLAG.BS),
        "attestedCredentialDataIncluded": bool(flags & AuthenticatorData.FLAG.AT),
        "extensionDataIncluded": bool(flags & AuthenticatorData.FLAG.ED),
        "flagsSet": [flag.name for flag in AuthenticatorData.FLAG if flags & flag],
    }

    details: Dict[str, Any] = {
        "rpIdHash": {
            "hex": auth_data.rp_id_hash.hex(),
            "base64url": encode_base64url(auth_data.rp_id_hash),
        },
        "flags": flag_details,
        "signCount": auth_data.counter,
    }

    credential_data = auth_data.credential_data
    if credential_data is not None:
        details["attestedCredentialData"] = {
            "aaguid": str(credential_data.aaguid),
            "aaguidHex": credential_data.aaguid.hex(),
            "credentialId": _binary_summary(credential_data.credential_id, "binary"),
            "publicKey": make_json_safe(dict(credential_data.public_key)),
        }

    extensions = auth_data.extensions
    if extensions is not None:
        extensions_payload: Dict[str, Any] = {
            "raw": make_json_safe(extensions),
        }
        if isinstance(extensions, Mapping):
            extensions_payload["summary"] = make_json_safe(
                summarize_authenticator_extensions(extensions)
            )
        details["extensions"] = extensions_payload

    return details


def _parse_attestation_object(data: bytes) -> Dict[str, Any]:
    attestation = AttestationObject(data)
    details: Dict[str, Any] = {
        "attestationFormat": attestation.fmt,
        "attestationStatement": make_json_safe(attestation.att_stmt),
        "authenticatorData": _describe_authenticator_data_bytes(bytes(attestation.auth_data)),
        "cbor": make_json_safe(cbor.decode(data)),
    }

    certificate_details = _extract_attestation_certificate(attestation.att_stmt)
    if certificate_details is not None:
        details["attestationCertificate"] = certificate_details

    return details


def _extract_attestation_certificate(att_stmt: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(att_stmt, Mapping):
        return None

    chain = att_stmt.get("x5c")
    if not isinstance(chain, Sequence) or not chain:
        return None

    first_entry = chain[0]
    cert_bytes: Optional[bytes]

    if isinstance(first_entry, str):
        cleaned = "".join(first_entry.split())
        padding = (-len(cleaned)) % 4
        try:
            cert_bytes = base64.b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            cert_bytes = None
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
    parsed: Mapping[str, Any], raw_text: Optional[str] = None
) -> Dict[str, Any]:
    details: Dict[str, Any] = {}

    type_value = parsed.get("type")
    if type_value is not None:
        details["type"] = type_value

    challenge_value = parsed.get("challenge")
    if challenge_value is not None:
        challenge_info: Dict[str, Any] = {"raw": challenge_value}
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


def _binary_summary(data: bytes, encoding: Optional[str] = None) -> Dict[str, Any]:
    summary = {
        "length": len(data),
        "base64": base64.b64encode(data).decode("ascii"),
        "base64url": encode_base64url(data),
        "hex": data.hex(),
        "colonHex": colon_hex(data),
    }
    if encoding:
        summary["encoding"] = encoding
    return summary


def _try_decode_utf8(data: bytes) -> Optional[str]:
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


def _prepare_decoder_response(result: Dict[str, Any]) -> Dict[str, Any]:
    format_label = result.get("format")
    return {
        "format": format_label,
        "inputEncoding": result.get("inputEncoding"),
        "detectedType": _base_type(format_label),
        "summary": _format_result_summary(result),
        "raw": result,
    }


def _format_result_summary(result: Dict[str, Any]) -> str:
    base_type = _base_type(result.get("format"))
    formatter = {
        "PublicKeyCredential": _format_public_key_credential_summary,
        "Attestation object": _format_attestation_object_summary,
        "Authenticator data": _format_authenticator_data_summary,
        "WebAuthn client data": _format_client_data_summary,
        "X.509 certificate": _format_certificate_summary,
        "JSON": _format_json_summary,
        "CBOR": _format_cbor_summary,
    }.get(base_type, _format_generic_summary)

    lines = formatter(result)
    return "\n".join(line for line in lines if line is not None).rstrip()


def _base_type(format_label: Optional[str]) -> str:
    if not format_label:
        return "Decoded data"
    separator = format_label.find(" (")
    if separator != -1:
        return format_label[:separator]
    return format_label


def _format_public_key_credential_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}
    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    authenticator_entry = response.get("authenticatorData") if isinstance(response, Mapping) else None

    attestation_details = attestation_entry.get("details") if isinstance(attestation_entry, Mapping) else None
    auth_details = None
    if isinstance(attestation_details, Mapping):
        auth_details = attestation_details.get("authenticatorData")
    if auth_details is None and isinstance(authenticator_entry, Mapping):
        auth_details = authenticator_entry.get("details")

    auth_bytes = _extract_authenticator_bytes(response, attestation_entry)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, auth_details, auth_bytes, response)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None)
    _extend_with_attestation_section(
        lines, attestation_entry, attestation_details, include_certificates=False
    )
    _extend_with_client_data_entry(lines, response.get("clientDataJSON") if isinstance(response, Mapping) else None)
    return lines


def _format_attestation_object_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None

    lines: List[str] = [f"Detected type:\t{base_type}"]
    attestation_entry: Dict[str, Any] = {"binary": result.get("binary")} if result.get("binary") else {}
    auth_bytes = _extract_authenticator_bytes_from_attestation(attestation_entry)
    _extend_with_authenticator_details(lines, auth_details, auth_bytes)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, None)
    _extend_with_attestation_section(
        lines, attestation_entry, decoded, include_certificates=False
    )
    return lines


def _format_authenticator_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_bytes = _extract_bytes_from_binary(result.get("binary"))

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, decoded, auth_bytes)
    _extend_with_authenticator_extensions(lines, decoded)
    _extend_with_client_extensions(lines, None)
    return lines


def _format_client_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_client_data_details(lines, decoded)
    return lines


def _format_certificate_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    certificate_lines = _build_certificate_summary_lines(decoded)
    if not certificate_lines:
        certificate_lines = _format_json_block(decoded)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _append_multiline_field(
        lines,
        "Certificate",
        certificate_lines,
        indent_str="",
        force_multiline=True,
    )
    return lines


def _format_json_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded")
    json_lines = _format_json_block(decoded)
    lines: List[str] = ["Detected type:\tJSON"]
    _append_multiline_field(lines, "JSON", json_lines, indent_str="  ")
    return lines


def _format_cbor_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded")
    json_lines = _format_json_block(decoded)
    lines: List[str] = ["Detected type:\tCBOR"]
    _append_multiline_field(lines, "CBOR as JSON", json_lines, indent_str="  ")
    return lines


def _format_generic_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    lines: List[str] = [f"Detected type:\t{base_type}"]

    decoded = result.get("decoded")
    if decoded is not None:
        _append_multiline_field(lines, "Decoded", _format_json_block(decoded), indent_str="  ")
    else:
        binary = result.get("binary")
        if binary is not None:
            _append_multiline_field(lines, "Binary", _format_json_block(binary), indent_str="  ")

    return lines


_DEVICE_IDENTIFIER_NAMES: Dict[str, str] = {
    "1.3.6.1.4.1.41482.1.1": "Security Key by Yubico Series",
}


def _build_certificate_summary_lines(decoded: Any) -> List[str]:
    if not isinstance(decoded, Mapping):
        return []

    lines: List[str] = []

    version = decoded.get("version")
    if isinstance(version, Mapping):
        display = version.get("display")
        if display:
            lines.append(f"Version: {display}")

    serial = decoded.get("serialNumber")
    if isinstance(serial, Mapping):
        decimal = serial.get("decimal")
        hex_value = serial.get("hex")
        if decimal and hex_value:
            lines.append(f"Certificate Serial Number: {decimal} ({hex_value})")
        elif decimal:
            lines.append(f"Certificate Serial Number: {decimal}")

    signature_algorithm = decoded.get("signatureAlgorithm")
    if signature_algorithm:
        lines.append(f"Signature Algorithm: {signature_algorithm}")

    issuer = decoded.get("issuer")
    if issuer:
        lines.append(f"Issuer: {issuer}")

    validity = decoded.get("validity")
    if isinstance(validity, Mapping):
        not_before = _format_certificate_time(validity.get("notBefore"))
        not_after = _format_certificate_time(validity.get("notAfter"))
        if not_before or not_after:
            lines.append("Validity")
            if not_before:
                lines.append(f"Not Before: {not_before}")
            if not_after:
                lines.append(f"Not After: {not_after}")

    subject = decoded.get("subject")
    if subject:
        lines.append(f"Subject: {subject}")

    lines.extend(_build_subject_public_key_info_lines(decoded.get("publicKeyInfo")))
    lines.extend(_build_certificate_extensions_lines(decoded.get("extensions")))
    lines.extend(_build_signature_lines(decoded.get("signature")))
    lines.extend(_build_fingerprint_lines(decoded.get("fingerprints")))

    ski_lines = _build_subject_key_identifier_lines(decoded)
    if ski_lines:
        lines.append("Subject key identifier:")
        lines.extend(ski_lines)

    return [line for line in lines if line is not None]


def _format_certificate_time(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        normalized = text.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            return text
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        return timestamp.isoformat()
    return None


def _build_subject_public_key_info_lines(info: Any) -> List[str]:
    if not isinstance(info, Mapping):
        return []

    lines: List[str] = ["Subject Public Key Info:"]

    key_type = info.get("type")
    if key_type:
        lines.append(f"Type: {key_type}")

    key_size = info.get("keySize")
    if isinstance(key_size, int):
        lines.append(f"Public-Key: ({key_size} bit)")

    point_lines = _format_public_key_point_lines(info.get("uncompressedPoint"))
    if point_lines:
        lines.append("pub:")
        lines.extend(point_lines)

    curve = info.get("curve")
    if not curve and isinstance(info.get("algorithm"), Mapping):
        curve = info["algorithm"].get("namedCurve")
    if curve:
        lines.append(f"Curve: {curve}")

    return [line for line in lines if line]


def _format_public_key_point_lines(point: Any) -> List[str]:
    if isinstance(point, str) and point.strip():
        return format_hex_string_lines(point)
    return []


def _build_certificate_extensions_lines(extensions: Any) -> List[str]:
    if not isinstance(extensions, list) or not extensions:
        return []

    lines: List[str] = ["X509v3 extensions:"]
    for extension in extensions:
        if not isinstance(extension, Mapping):
            continue
        header = _format_certificate_extension_header(extension)
        if header:
            lines.append(f"{header}:")
        value_lines = _format_certificate_extension_value(extension.get("value"))
        lines.extend(value_lines)
    return lines


def _format_certificate_extension_header(extension: Mapping[str, Any]) -> Optional[str]:
    display_header = extension.get("displayHeader")
    if isinstance(display_header, str) and display_header.strip():
        return display_header.strip()

    include_oid = extension.get("includeOidInHeader", True)
    oid = extension.get("oid")
    friendly = extension.get("friendlyName") or extension.get("name")

    parts: List[str] = []
    if include_oid and oid:
        parts.append(str(oid))
    if friendly and friendly != oid:
        friendly_part = f"({friendly})" if include_oid and parts else str(friendly)
        parts.append(friendly_part)

    if not parts:
        if oid:
            parts.append(str(oid))
        elif friendly:
            parts.append(str(friendly))
        else:
            return None

    return " ".join(parts)


def _format_certificate_extension_value(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, Mapping):
        lines: List[str] = []
        hex_value = None
        device_identifier = None

        for key, entry in value.items():
            if entry in (None, ""):
                continue
            key_lower = str(key).lower()
            if key_lower == "hex value":
                hex_value = str(entry)
            elif key_lower == "device identifier":
                device_identifier = entry
            elif isinstance(entry, (Mapping, list, tuple)):
                lines.append(f"{key}:")
                lines.extend(_format_certificate_extension_value(entry))
            else:
                lines.append(f"{key}: {entry}")

        ordered: List[str] = []
        if hex_value is not None:
            ordered.append(f"Hex value: {hex_value}")
        if device_identifier is not None:
            ordered.append(_format_device_identifier_line(device_identifier))
        ordered.extend(lines)
        return ordered

    if isinstance(value, (list, tuple)):
        lines: List[str] = []
        for item in value:
            if item in (None, ""):
                continue
            if isinstance(item, (Mapping, list, tuple)):
                lines.extend(_format_certificate_extension_value(item))
            else:
                lines.append(str(item))
        return lines

    return [str(value)]


def _format_device_identifier_line(identifier: Any) -> str:
    if not isinstance(identifier, str):
        return str(identifier)
    cleaned = identifier.strip()
    friendly = _DEVICE_IDENTIFIER_NAMES.get(cleaned)
    return f"{cleaned} ({friendly})" if friendly else cleaned


def _build_signature_lines(signature: Any) -> List[str]:
    if not isinstance(signature, Mapping):
        return []

    lines: List[str] = []
    algorithm = signature.get("algorithm")
    if algorithm:
        lines.append(f"Signature Algorithm: {algorithm}")

    hex_lines: List[str]
    signature_lines = signature.get("lines")
    if isinstance(signature_lines, list) and signature_lines:
        hex_lines = [line for line in signature_lines if line]
    else:
        hex_value = signature.get("hex")
        if isinstance(hex_value, str) and hex_value.strip():
            hex_lines = format_hex_string_lines(hex_value)
        else:
            hex_lines = []

    lines.extend(hex_lines)
    return lines


def _build_fingerprint_lines(fingerprints: Any) -> List[str]:
    if not isinstance(fingerprints, Mapping):
        return []

    ordered: List[Tuple[str, List[str]]] = []
    for label in ("md5", "sha1", "sha256"):
        value = fingerprints.get(label)
        if isinstance(value, str) and value.strip():
            ordered.append((label.upper(), format_hex_string_lines(value)))

    if not ordered:
        return []

    lines: List[str] = ["Fingerprint:"]
    for name, hex_lines in ordered:
        lines.append(f"{name}:")
        lines.extend(hex_lines)
    return lines


def _build_subject_key_identifier_lines(decoded: Mapping[str, Any]) -> List[str]:
    extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if isinstance(extensions, list):
        for extension in extensions:
            if not isinstance(extension, Mapping):
                continue
            oid = str(extension.get("oid") or "")
            if oid == "2.5.29.14":
                value = extension.get("value")
                if isinstance(value, Mapping):
                    for key in ("Subject Key Identifier", "subjectKeyIdentifier", "value"):
                        digest = value.get(key)
                        if isinstance(digest, str) and digest.strip():
                            return format_hex_string_lines(digest)
                raw_bytes = extension.get("bytes")
                if isinstance(raw_bytes, (bytes, bytearray)):
                    return format_hex_bytes_lines(bytes(raw_bytes))

    if isinstance(decoded, Mapping):
        der_b64 = decoded.get("derBase64")
        if isinstance(der_b64, str) and der_b64.strip():
            try:
                der_bytes = base64.b64decode(der_b64, validate=True)
            except (ValueError, binascii.Error):
                der_bytes = None
            if der_bytes:
                try:
                    certificate = x509.load_der_x509_certificate(der_bytes)
                except Exception:
                    certificate = None
                if certificate is not None:
                    try:
                        ski_extension = certificate.extensions.get_extension_for_oid(
                            ExtensionOID.SUBJECT_KEY_IDENTIFIER
                        )
                    except x509.ExtensionNotFound:
                        try:
                            derived = x509.SubjectKeyIdentifier.from_public_key(
                                certificate.public_key()
                            )
                        except Exception:
                            digest_bytes = None
                        else:
                            digest_bytes = derived.digest
                    else:
                        digest_bytes = ski_extension.value.digest
                    if digest_bytes:
                        return format_hex_bytes_lines(digest_bytes)

    public_key_info = decoded.get("publicKeyInfo") if isinstance(decoded, Mapping) else None
    if isinstance(public_key_info, Mapping):
        spki_b64 = public_key_info.get("subjectPublicKeyInfoBase64")
        if isinstance(spki_b64, str) and spki_b64.strip():
            cleaned = re.sub(r"\s+", "", spki_b64)
            try:
                spki_bytes = base64.b64decode(cleaned, validate=True)
            except (ValueError, binascii.Error):
                pass
            else:
                digest = hashlib.sha1(spki_bytes).digest()
                return format_hex_bytes_lines(digest)

    return []


def _append_simple_field(lines: List[str], label: str, value: Optional[Any], default: str = "(none)") -> None:
    if value is None:
        lines.append(f"{label}:\t{default}")
    else:
        lines.append(f"{label}:\t{value}")


def _append_multiline_field(
    lines: List[str],
    label: str,
    content_lines: Iterable[str],
    *,
    indent_str: str = "",
    default: str = "(none)",
    force_multiline: bool = False,
) -> None:
    filtered = [line for line in content_lines if line is not None]
    if not filtered:
        lines.append(f"{label}:\t{default}")
        return
    if len(filtered) == 1 and not force_multiline:
        lines.append(f"{label}:\t{filtered[0]}")
        return
    lines.append(f"{label}:\t")
    prefix = indent_str
    for line in filtered:
        lines.append(f"{prefix}{line}")


def _format_json_block(value: Any) -> List[str]:
    if value is None:
        return []
    try:
        return json.dumps(value, indent=2, sort_keys=False).splitlines()
    except (TypeError, ValueError):
        return [str(value)]


def _format_boolean(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and value in (0, 1):
        return "true" if bool(value) else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered
    return None


def _format_counter_value(counter: Any) -> Optional[str]:
    try:
        count = int(counter)
    except (TypeError, ValueError):
        return None
    if count < 0:
        return str(count)
    return f"0x{count:08x}={count}"


def _format_flag_line(flags: Any) -> Optional[str]:
    if not isinstance(flags, Mapping):
        return None
    try:
        value = int(flags.get("value"))
    except (TypeError, ValueError):
        return None
    bitfield = flags.get("bitfield")
    if not isinstance(bitfield, str) or not bitfield.startswith("0b"):
        bitfield = f"0b{value:08b}"
    components = [
        f"UP:{1 if flags.get('userPresent') else 0}",
        f"UV:{1 if flags.get('userVerified') else 0}",
        f"BE:{1 if flags.get('backupEligibility') else 0}",
        f"BS:{1 if flags.get('backupState') else 0}",
        f"AT:{1 if flags.get('attestedCredentialDataIncluded') else 0}",
        f"ED:{1 if flags.get('extensionDataIncluded') else 0}",
    ]
    return f"0x{value:02x}={bitfield}= {' '.join(components)}"


def _build_authenticator_data_lines(
    auth_bytes: Optional[bytes], auth_details: Optional[Mapping[str, Any]]
) -> List[str]:
    if auth_bytes:
        rp = auth_bytes[:32].hex()
        lines = [rp]
        if len(auth_bytes) > 32:
            lines.append(auth_bytes[32:33].hex())
        if len(auth_bytes) > 33:
            lines.append(auth_bytes[33:37].hex())
        if len(auth_bytes) > 37:
            remainder = auth_bytes[37:].hex()
            if remainder:
                lines.append(remainder)
        return lines

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
            if isinstance(rp_hex, str) and rp_hex:
                return [rp_hex]

    return []


def _parse_attested_data(auth_bytes: Optional[bytes]) -> Optional[Dict[str, bytes]]:
    if not auth_bytes or len(auth_bytes) <= 37:
        return None
    remainder = auth_bytes[37:]
    if len(remainder) < 18:
        return {"raw": remainder}
    aaguid = remainder[:16]
    length_bytes = remainder[16:18]
    credential_length = int.from_bytes(length_bytes, "big")
    credential_section = remainder[18:]
    if len(credential_section) < credential_length:
        credential_id = credential_section
        public_key = b""
    else:
        credential_id = credential_section[:credential_length]
        public_key = credential_section[credential_length:]
    return {
        "aaguid": aaguid,
        "length_bytes": length_bytes,
        "credential_id": credential_id,
        "public_key": public_key,
    }


def _collect_attested_info(
    attested: Mapping[str, Any], auth_bytes: Optional[bytes], fallback_alg: Optional[Any] = None
) -> Dict[str, Any]:
    parsed = _parse_attested_data(auth_bytes)
    credential_lines: List[str] = []
    credential_id_hex: Optional[str] = None
    aaguid_lines: List[str] = []

    if parsed and "aaguid" in parsed and isinstance(parsed["aaguid"], bytes):
        credential_lines.append(parsed["aaguid"].hex())
        aaguid_hex = parsed["aaguid"].hex()
    else:
        aaguid_hex = attested.get("aaguidHex") if isinstance(attested, Mapping) else None
        if isinstance(aaguid_hex, str):
            credential_lines.append(aaguid_hex)

    aaguid_display = attested.get("aaguid") if isinstance(attested, Mapping) else None
    if isinstance(aaguid_display, str) and aaguid_display:
        aaguid_lines.extend(filter(None, [aaguid_hex, aaguid_display]))
    elif aaguid_hex:
        aaguid_lines.append(aaguid_hex)

    if parsed and "length_bytes" in parsed and isinstance(parsed["length_bytes"], bytes):
        credential_lines.append(parsed["length_bytes"].hex())
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            length = credential.get("length")
            if isinstance(length, int):
                credential_lines.append(length.to_bytes(2, "big").hex())

    if parsed and "credential_id" in parsed and isinstance(parsed["credential_id"], bytes):
        credential_id_hex = parsed["credential_id"].hex()
        credential_lines.append(credential_id_hex)
    else:
        credential = attested.get("credentialId") if isinstance(attested, Mapping) else None
        if isinstance(credential, Mapping):
            credential_id_hex = credential.get("hex")
            if isinstance(credential_id_hex, str):
                credential_lines.append(credential_id_hex)

    if parsed and "public_key" in parsed and isinstance(parsed["public_key"], bytes):
        public_key_bytes = parsed["public_key"]
        if public_key_bytes:
            credential_lines.append(public_key_bytes.hex())
    else:
        public_key_bytes = b""

    public_key = attested.get("publicKey") if isinstance(attested, Mapping) else None
    algorithm_label = _resolve_cose_algorithm(public_key, fallback_alg)
    public_key_lines = _format_json_block(_convert_cose_key_for_display(public_key))

    info = {
        "credential_lines": credential_lines,
        "aaguid_lines": aaguid_lines or ([aaguid_hex] if aaguid_hex else []),
        "credential_id": credential_id_hex,
        "algorithm": algorithm_label,
        "public_key_lines": public_key_lines,
    }

    has_content = any(
        bool(info.get(key)) for key in ("credential_lines", "aaguid_lines", "credential_id", "public_key_lines")
    )
    return info if has_content else {}


_COSE_ALG_LABELS: Dict[int, str] = {
    -8: "EdDSA",
    -7: "ES256",
    -35: "ES256K",
    -36: "ES384",
    -37: "ES512",
    -257: "RS256",
    -258: "RS384",
    -259: "RS512",
}


def _resolve_cose_algorithm(public_key: Any, fallback: Optional[Any] = None) -> Optional[str]:
    alg_value: Optional[Any] = None
    if isinstance(public_key, Mapping):
        if 3 in public_key:
            alg_value = public_key[3]
        elif "3" in public_key:
            alg_value = public_key["3"]
        elif "alg" in public_key:
            alg_value = public_key["alg"]

    if alg_value is None:
        if isinstance(fallback, Mapping):
            alg_value = fallback.get("publicKeyAlgorithm")
        elif isinstance(fallback, int):
            alg_value = fallback

    if alg_value is None:
        return None

    try:
        alg_int = int(alg_value)
    except (TypeError, ValueError):
        return str(alg_value)
    return _COSE_ALG_LABELS.get(alg_int, str(alg_int))


def _convert_cose_key_for_display(public_key: Any) -> Any:
    if isinstance(public_key, Mapping):
        return {key: _convert_cose_key_for_display(value) for key, value in public_key.items()}
    if isinstance(public_key, list):
        return [_convert_cose_key_for_display(item) for item in public_key]
    if isinstance(public_key, str):
        decoded = _decode_base64_field(public_key)
        if decoded is not None:
            return decoded.hex()
    return public_key


def _decode_base64_field(value: str) -> Optional[bytes]:
    cleaned = value.strip()
    if not cleaned:
        return None
    normalized = cleaned.replace('-', '+').replace('_', '/')
    padding = (-len(normalized)) % 4
    try:
        decoded = base64.b64decode(normalized + '=' * padding)
    except (ValueError, binascii.Error):
        return None

    if base64.urlsafe_b64encode(decoded).rstrip(b'=') == cleaned.encode('ascii').rstrip(b'='):
        return decoded
    if base64.b64encode(decoded).rstrip(b'=') == normalized.encode('ascii').rstrip(b'='):
        return decoded
    return None


def _extract_hex_from_binary(entry: Any) -> Optional[str]:
    if not isinstance(entry, Mapping):
        return None
    direct_hex = entry.get("hex")
    if isinstance(direct_hex, str) and direct_hex:
        return direct_hex
    binary = entry.get("binary")
    if isinstance(binary, Mapping):
        hex_value = binary.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def _extract_bytes_from_binary(entry: Any) -> Optional[bytes]:
    if not isinstance(entry, Mapping):
        return None
    hex_value = _extract_hex_from_binary(entry)
    if isinstance(hex_value, str):
        cleaned = "".join(hex_value.split())
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        cleaned = "".join(raw_value.split())
        padding = (-len(cleaned)) % 4
        try:
            return base64.urlsafe_b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            return None

    return None


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> Optional[bytes]:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = _extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return _extract_authenticator_bytes_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> Optional[bytes]:
    attestation_bytes = _extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            cleaned = "".join(raw_value.split())
            padding = (-len(cleaned)) % 4
            try:
                attestation_bytes = base64.b64decode(cleaned + "=" * padding)
            except (ValueError, binascii.Error):
                attestation_bytes = None

    if attestation_bytes is None:
        return None

    try:
        attestation = AttestationObject(attestation_bytes)
    except Exception:  # pragma: no cover - defensive against malformed input
        return None

    try:
        return bytes(attestation.auth_data)
    except Exception:  # pragma: no cover - defensive
        return None


def _extend_with_authenticator_details(
    lines: List[str],
    auth_details: Optional[Mapping[str, Any]],
    auth_bytes: Optional[bytes],
    response_context: Optional[Mapping[str, Any]] = None,
) -> None:
    data_lines = _build_authenticator_data_lines(auth_bytes, auth_details)
    _append_multiline_field(lines, "Authenticator data", data_lines)

    rp_hex = None
    flags_info = None
    sign_count = None
    attested_info: Optional[Dict[str, Any]] = None

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
        flags_info = auth_details.get("flags")
        sign_count = auth_details.get("signCount")
        attested = auth_details.get("attestedCredentialData")
        if isinstance(attested, Mapping):
            fallback_alg = None
            if isinstance(response_context, Mapping):
                fallback_alg = response_context.get("publicKeyAlgorithm")
            attested_info = _collect_attested_info(attested, auth_bytes, fallback_alg)

    _append_simple_field(lines, "RP ID hash", rp_hex)
    flag_line = _format_flag_line(flags_info)
    _append_multiline_field(
        lines,
        "Flags",
        [flag_line] if flag_line else [],
        force_multiline=True,
    )
    _append_simple_field(lines, "Counter", _format_counter_value(sign_count))

    if attested_info:
        _append_multiline_field(lines, "Credential data", attested_info.get("credential_lines", []))
        _append_multiline_field(lines, "AAGUID", attested_info.get("aaguid_lines", []))
        _append_simple_field(lines, "Credential ID", attested_info.get("credential_id"))
        _append_simple_field(lines, "Key algorithm", attested_info.get("algorithm"))
        _append_multiline_field(
            lines,
            "Public key",
            attested_info.get("public_key_lines", []),
            indent_str="  ",
        )


def _extend_with_authenticator_extensions(lines: List[str], auth_details: Any) -> None:
    if not isinstance(auth_details, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    extensions = auth_details.get("extensions")
    if not isinstance(extensions, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    summary = extensions.get("summary")
    raw_value = extensions.get("raw")
    content = summary if summary is not None else raw_value
    if content is None:
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    _append_multiline_field(lines, "Authenticator extensions", _format_json_block(content), indent_str="  ")


def _extend_with_client_extensions(lines: List[str], extensions: Any) -> None:
    if extensions is None:
        _append_simple_field(lines, "Client extensions", None)
        return
    _append_multiline_field(lines, "Client extensions", _format_json_block(extensions), indent_str="  ")


def _extend_with_attestation_section(
    lines: List[str],
    attestation_entry: Any,
    attestation_details: Any,
    *,
    include_certificates: bool = True,
) -> None:
    att_hex = _extract_hex_from_binary(attestation_entry)
    _append_simple_field(lines, "Attestation object", att_hex)

    att_format = None
    certificates = None
    if isinstance(attestation_details, Mapping):
        att_format = attestation_details.get("attestationFormat")
        certificates = attestation_details.get("attestationCertificate")

    _append_simple_field(lines, "Att. format", att_format)

    if not include_certificates:
        lines.append("Att. certificates:\t")
        return

    if isinstance(certificates, Mapping):
        summary = certificates.get("summary")
        if isinstance(summary, str) and summary.strip():
            cert_lines = summary.splitlines()
        else:
            cert_lines = _format_json_block(certificates)
        _append_multiline_field(lines, "Att. certificates", cert_lines, indent_str="  ")
    else:
        _append_simple_field(lines, "Att. certificates", None)


def _extend_with_client_data_entry(lines: List[str], client_data_entry: Any) -> None:
    details = None
    if isinstance(client_data_entry, Mapping):
        details = client_data_entry.get("details")
    _extend_with_client_data_details(lines, details)


def _extend_with_client_data_details(lines: List[str], details: Any) -> None:
    if not isinstance(details, Mapping):
        _append_simple_field(lines, "Client data", None)
        _append_simple_field(lines, "Type", None)
        _append_simple_field(lines, "Challenge", None)
        _append_simple_field(lines, "Origin", None)
        _append_simple_field(lines, "Cross-origin", None)
        return

    raw_json = details.get("rawJson")
    client_data_lines: List[str]
    if isinstance(raw_json, Mapping):
        client_data_lines = _format_json_block(raw_json)
    else:
        raw_text = details.get("rawText")
        if isinstance(raw_text, str) and raw_text.strip():
            client_data_lines = raw_text.splitlines()
        else:
            filtered = {
                key: details.get(key)
                for key in ("type", "challenge", "origin", "crossOrigin")
                if key in details
            }
            client_data_lines = _format_json_block(filtered)

    _append_multiline_field(lines, "Client data", client_data_lines, indent_str="  ")

    type_value = details.get("type")
    challenge = details.get("challenge")
    if isinstance(challenge, Mapping):
        challenge_value = challenge.get("hex") or challenge.get("raw")
    else:
        challenge_value = challenge
    origin = details.get("origin")
    cross_origin_value = details.get("crossOrigin")
    cross_origin_text = _format_boolean(cross_origin_value)
    if cross_origin_text is None and cross_origin_value is not None:
        cross_origin_text = str(cross_origin_value)

    _append_simple_field(lines, "Type", type_value)
    _append_simple_field(lines, "Challenge", challenge_value)
    _append_simple_field(lines, "Origin", origin)
    _append_simple_field(lines, "Cross-origin", cross_origin_text)
