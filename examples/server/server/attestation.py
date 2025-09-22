"""Attestation and credential helper utilities."""
from __future__ import annotations

import base64
import hashlib
import math
import re
import string
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple

from fido2.attestation import Attestation, InvalidData, InvalidSignature, UnsupportedType
from fido2.cose import CoseKey
from fido2.utils import ByteBuffer, websafe_decode
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    RegistrationResponse,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .metadata import get_mds_verifier

__all__ = [
    "CRED_PROTECT_LABELS",
    "EXTENSION_DISPLAY_METADATA",
    "augment_aaguid_fields",
    "coerce_aaguid_hex",
    "describe_cred_protect",
    "encode_base64url",
    "extract_attestation_details",
    "extract_min_pin_length",
    "format_hex_bytes_lines",
    "make_json_safe",
    "perform_attestation_checks",
    "serialize_attestation_certificate",
    "summarize_authenticator_extensions",
]


def _ensure_utc_datetime(value: datetime) -> datetime:
    """Return ``value`` normalised to a timezone-aware UTC datetime."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _certificate_datetime(cert: x509.Certificate, attribute: str) -> datetime:
    """Retrieve *attribute* from *cert* preferring the UTC variant if present."""

    utc_attribute = f"{attribute}_utc"
    value = getattr(cert, utc_attribute, None)
    if value is None:
        value = getattr(cert, attribute)
    return _ensure_utc_datetime(value)


def colon_hex(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def format_hex_bytes_lines(data: bytes, bytes_per_line: int = 16) -> List[str]:
    """Return colon separated hex grouped across multiple lines."""
    if not data:
        return []

    hex_pairs = [f"{byte:02x}" for byte in data]
    lines = []
    for start in range(0, len(hex_pairs), bytes_per_line):
        chunk = hex_pairs[start : start + bytes_per_line]
        if not chunk:
            continue
        lines.append(":".join(chunk))
    return lines


def format_hex_string_lines(hex_string: str, bytes_per_line: int = 16) -> List[str]:
    cleaned = "".join(hex_string.split()).replace(":", "")
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return [hex_string]
    return format_hex_bytes_lines(data, bytes_per_line)


def decode_asn1_octet_string(data: bytes) -> bytes:
    """Best-effort decode of a DER-encoded OCTET STRING payload."""

    current = data
    for _ in range(4):
        if not current or current[0] != 0x04 or len(current) < 2:
            break

        length_byte = current[1]
        offset = 2

        if length_byte == 0x80:
            break

        if length_byte & 0x80:
            length_octets = length_byte & 0x7F
            if length_octets == 0 or len(current) < offset + length_octets:
                break
            length = int.from_bytes(current[offset : offset + length_octets], "big")
            offset += length_octets
        else:
            length = length_byte

        if len(current) < offset + length:
            break

        next_value = current[offset : offset + length]
        if next_value == current:
            break
        current = next_value

    return current


EXTENSION_DISPLAY_METADATA: Dict[str, Dict[str, Any]] = {
    "1.3.6.1.4.1.45724.1.1.4": {
        "friendly_name": "FIDO: Device AAGUID",
    },
    "1.3.6.1.4.1.45724.2.1.1": {
        "friendly_name": "FIDO: Transports",
    },
    "2.5.29.14": {
        "friendly_name": "Subject key id",
    },
    "2.5.29.35": {
        "friendly_name": "Authority key identifier",
    },
    "2.5.29.19": {
        "friendly_name": "X509v3 Basic Constraints",
        "header": "X509v3 Basic Constraints",
        "include_oid_in_header": False,
    },
}


def encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_json_safe(value: Any) -> Any:
    """Recursively convert bytes-like WebAuthn option values into JSON-friendly data."""
    if isinstance(value, (bytes, bytearray, memoryview, ByteBuffer)):
        return encode_base64url(bytes(value))
    if isinstance(value, Mapping):
        return {key: make_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]
    return value


CRED_PROTECT_LABELS: Dict[Any, str] = {
    1: "userVerificationOptional",
    2: "userVerificationOptionalWithCredentialIDList",
    3: "userVerificationRequired",
    "userVerificationOptional": "userVerificationOptional",
    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationRequired": "userVerificationRequired",
}


def describe_cred_protect(value: Any) -> Any:
    """Return a human readable credProtect description when possible."""
    return CRED_PROTECT_LABELS.get(value, value)


def coerce_non_negative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        if math.isfinite(value) and value >= 0:
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = int(stripped, 10)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def normalize_aaguid_string(value: Any) -> Optional[str]:
    if isinstance(value, str):
        cleaned = ''.join(ch for ch in value if ch in string.hexdigits)
        if len(cleaned) == 32:
            return cleaned.lower()
    return None


def coerce_aaguid_hex(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        hex_value = bytes(value).hex()
        return hex_value if len(hex_value) == 32 else None

    if isinstance(value, str):
        normalized = normalize_aaguid_string(value)
        if normalized and len(normalized) == 32:
            return normalized
        return None

    if isinstance(value, Mapping):
        for key in ("aaguid", "hex", "raw", "value", "guid"):
            candidate = coerce_aaguid_hex(value.get(key))
            if candidate:
                return candidate
        return None

    try:
        raw_bytes = bytes(value)
    except Exception:
        return None

    hex_value = raw_bytes.hex()
    if len(hex_value) != 32:
        return None
    return hex_value


def augment_aaguid_fields(container: MutableMapping[str, Any]) -> None:
    if not isinstance(container, MutableMapping):
        return

    raw_value = container.get("aaguid")
    aaguid_hex: Optional[str] = None

    if isinstance(raw_value, (bytes, bytearray, memoryview)):
        aaguid_hex = bytes(raw_value).hex()
    elif isinstance(raw_value, str):
        aaguid_hex = normalize_aaguid_string(raw_value)
    elif isinstance(raw_value, Mapping):
        for key in ("hex", "raw", "value"):
            candidate = raw_value.get(key)
            if isinstance(candidate, str):
                normalized = normalize_aaguid_string(candidate)
                if normalized:
                    aaguid_hex = normalized
                    break

    if aaguid_hex:
        container["aaguid"] = aaguid_hex
        container["aaguidHex"] = aaguid_hex
        container["aaguidRaw"] = aaguid_hex
        try:
            container["aaguidGuid"] = str(uuid.UUID(hex=aaguid_hex))
        except ValueError:
            container.pop("aaguidGuid", None)
    else:
        container.pop("aaguidHex", None)
        container.pop("aaguidGuid", None)
        container.pop("aaguidRaw", None)


def extract_min_pin_length(extension_results: Any) -> Optional[int]:
    if not isinstance(extension_results, Mapping):
        return None

    raw_value = extension_results.get("minPinLength")
    candidate = coerce_non_negative_int(raw_value)
    if candidate is not None:
        return candidate

    if isinstance(raw_value, Mapping):
        for key in ("minPinLength", "minimumPinLength", "value"):
            nested_candidate = coerce_non_negative_int(raw_value.get(key))
            if nested_candidate is not None:
                return nested_candidate

    return None


def summarize_authenticator_extensions(extensions: Mapping[str, Any]) -> Dict[str, Any]:
    """Augment authenticator extension outputs with human friendly metadata."""
    summary: Dict[str, Any] = {}
    for name, ext_value in extensions.items():
        summary[name] = ext_value
        if name == "credProtect":
            summary["credProtectLabel"] = describe_cred_protect(ext_value)
    return summary


def extract_attestation_details(
    response: Any,
) -> Tuple[
    str,
    Dict[str, Any],
    Optional[str],
    Optional[str],
    Dict[str, Any],
    Optional[Dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""
    attestation_format = "none"
    attestation_statement: Dict[str, Any] = {}
    attestation_object_b64: Optional[str] = None
    client_data_b64: Optional[str] = None
    client_extension_results: Dict[str, Any] = {}
    attestation_certificate: Optional[Dict[str, Any]] = None

    if not isinstance(response, dict):
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:  # pragma: no cover - debugging aid
        print(f"[DEBUG] Failed to parse registration response for attestation: {exc}")
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = encode_base64url(bytes(attestation_object))

    if isinstance(attestation_statement, Mapping):
        cert_chain = attestation_statement.get("x5c") or []
        if isinstance(cert_chain, (list, tuple)) and cert_chain:
            try:
                first_cert = cert_chain[0]
                if isinstance(first_cert, str):
                    cert_bytes = base64.b64decode(first_cert)
                else:
                    cert_bytes = bytes(first_cert)
                attestation_certificate = serialize_attestation_certificate(cert_bytes)
            except Exception as cert_error:
                attestation_certificate = {"error": str(cert_error)}

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = encode_base64url(bytes(client_data))

    extension_outputs = registration.client_extension_results
    if extension_outputs:
        if isinstance(extension_outputs, dict):
            client_extension_results = extension_outputs
        elif isinstance(extension_outputs, Mapping):
            client_extension_results = dict(extension_outputs)
        else:
            client_extension_results = extension_outputs  # type: ignore[assignment]

    return (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        client_extension_results,
        attestation_certificate,
    )


def format_x509_name(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


_HASH_NORMALISE_PATTERN = re.compile(r"sha-?(\d{3})$", re.IGNORECASE)


def _format_algorithm_component(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text or text == "—":
        return ""
    return text.replace(" ", "")


def _format_hash_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    match = _HASH_NORMALISE_PATTERN.match(text)
    if match:
        return f"SHA{match.group(1)}"
    return text.replace("-", "").replace(" ", "").upper()


def _derive_certificate_algorithm_info(public_key_info: Mapping[str, Any], signature_info: Mapping[str, Any]) -> str:
    if not isinstance(public_key_info, Mapping):
        return ""

    algorithm = public_key_info.get("algorithm", {})
    if not isinstance(algorithm, Mapping):
        algorithm = {}

    named_curve = algorithm.get("namedCurve") or public_key_info.get("curve")
    key_type = public_key_info.get("type")
    modulus_length = algorithm.get("modulusLength") or public_key_info.get("keySize")

    key_component = ""
    if named_curve:
        key_component = named_curve
    elif key_type:
        key_text = str(key_type)
        if key_text.upper().startswith("RSA") and modulus_length:
            key_component = f"RSA{modulus_length}"
        else:
            key_component = key_text
    elif algorithm.get("name"):
        key_component = algorithm["name"]

    algorithm_name = algorithm.get("name") or key_type or ""
    if not algorithm_name and isinstance(signature_info, Mapping):
        algorithm_name = signature_info.get("algorithm") or ""

    hash_component = ""
    if isinstance(signature_info, Mapping):
        hash_info = signature_info.get("hash")
        if isinstance(hash_info, Mapping):
            hash_component = hash_info.get("name") or ""
        elif hash_info not in (None, ""):
            hash_component = hash_info
        if not hash_component:
            sig_name = signature_info.get("algorithm")
            if isinstance(sig_name, str):
                lowered = sig_name.lower()
                if "ed25519" in lowered:
                    hash_component = "SHA512"
                elif "ed448" in lowered:
                    hash_component = "SHAKE256"

    components = []
    for part in (
        _format_algorithm_component(key_component),
        _format_algorithm_component(algorithm_name),
        _format_hash_value(hash_component),
    ):
        if part and (not components or part.lower() != components[-1].lower()):
            components.append(part)

    return "_".join(components)


def _extract_common_names(name: x509.Name) -> List[str]:
    values: List[str] = []
    for attribute in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = attribute.value
        if isinstance(value, str):
            text = value.strip()
            if text:
                values.append(text)
    return values


def serialize_attestation_certificate(cert_bytes: bytes):
    if not cert_bytes:
        return None

    certificate = x509.load_der_x509_certificate(cert_bytes)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    def _isoformat(value: datetime) -> str:
        return _ensure_utc_datetime(value).isoformat()

    not_valid_before = _certificate_datetime(certificate, "not_valid_before")
    not_valid_after = _certificate_datetime(certificate, "not_valid_after")

    extensions = []
    for ext in certificate.extensions:
        oid = ext.oid.dotted_string
        metadata = EXTENSION_DISPLAY_METADATA.get(oid, {})
        metadata_friendly = metadata.get("friendly_name")
        default_name = getattr(ext.oid, "_name", None)
        include_oid = metadata.get("include_oid_in_header")
        extensions.append(
            {
                "oid": oid,
                "name": metadata_friendly or default_name or oid,
                "friendlyName": metadata_friendly,
                "critical": ext.critical,
                "value": _serialize_extension_value(ext),
                "displayHeader": metadata.get("header"),
                "includeOidInHeader": True if include_oid is None else bool(include_oid),
            }
        )

    fingerprints = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "md5": certificate.fingerprint(hashes.MD5()).hex(),
    }

    der_bytes = certificate.public_bytes(serialization.Encoding.DER)
    der_base64 = base64.b64encode(der_bytes).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    summary_lines: List[str] = []

    def _append_line(line: str) -> None:
        summary_lines.append(line)

    def _append_blank_line() -> None:
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")

    signature_algorithm = getattr(
        certificate.signature_algorithm_oid,
        "_name",
        certificate.signature_algorithm_oid.dotted_string,
    )
    issuer_str = format_x509_name(certificate.issuer)
    subject_str = format_x509_name(certificate.subject)
    public_key = certificate.public_key()
    public_key_info = _serialize_public_key_info(public_key)
    signature_bytes = certificate.signature
    signature_lines = format_hex_bytes_lines(signature_bytes)
    signature_hex = signature_bytes.hex()
    signature_colon = colon_hex(signature_bytes)

    try:
        signature_hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # pragma: no cover - cryptography may raise if unavailable
        signature_hash_algorithm = None
    if signature_hash_algorithm is not None:
        hash_name = getattr(signature_hash_algorithm, "name", None)
        if not hash_name:
            hash_name = signature_hash_algorithm.__class__.__name__
        signature_hash = {"name": hash_name}
    else:
        signature_hash = None

    serial_decimal = str(certificate.serial_number)
    serial_hex = f"0x{certificate.serial_number:x}"

    _append_line(f"Version: {version_number} ({version_hex})")
    _append_line(
        f"Certificate Serial Number: {serial_decimal} ({serial_hex})"
    )
    _append_line(f"Signature Algorithm: {signature_algorithm}")
    _append_line(f"Issuer: {issuer_str}")

    _append_blank_line()
    _append_line("Validity:")
    _append_line(f"    Not Before: {_isoformat(not_valid_before)}")
    _append_line(f"    Not After: {_isoformat(not_valid_after)}")

    _append_blank_line()
    _append_line(f"Subject: {subject_str}")

    pk_summary_entries: List[Tuple[str, Any]] = []
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        pk_summary_entries.append(("Type", "ECC"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        ecc_point_lines = format_hex_bytes_lines(
            public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )
        if ecc_point_lines:
            pk_summary_entries.append(("pub", ecc_point_lines))
        curve_name = getattr(public_key.curve, "name", None)
        if curve_name:
            pk_summary_entries.append(("Curve", curve_name))
    elif isinstance(public_key, rsa.RSAPublicKey):
        pk_summary_entries.append(("Type", "RSA"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        numbers = public_key.public_numbers()
        modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        modulus_lines = format_hex_bytes_lines(modulus_bytes)
        if modulus_lines:
            pk_summary_entries.append(("Modulus", modulus_lines))
        pk_summary_entries.append(("Exponent", str(numbers.e)))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_type = "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
        pk_summary_entries.append(("Type", key_type))
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        raw_lines = format_hex_bytes_lines(raw_bytes)
        if raw_lines:
            pk_summary_entries.append(("Public Key", raw_lines))
    else:
        pk_summary_entries.append(("Type", public_key.__class__.__name__))

    if pk_summary_entries:
        _append_blank_line()
        _append_line("Subject Public Key Info:")
        for label, value in pk_summary_entries:
            if value is None or (isinstance(value, list) and not value):
                continue
            if isinstance(value, list):
                _append_line(f"    {label}:")
                for line in value:
                    _append_line(f"        {line}")
            else:
                _append_line(f"    {label}: {value}")

    if extensions:
        _append_blank_line()
        _append_line("X509v3 extensions:")

        def _append_structured(value: Any, indent: int) -> None:
            indent_str = " " * 4 * indent
            if value is None:
                return
            if isinstance(value, Mapping):
                for key, val in value.items():
                    if val in (None, ""):
                        continue
                    if isinstance(val, (Mapping, list, tuple)):
                        _append_line(f"{indent_str}{key}:")
                        _append_structured(val, indent + 1)
                    else:
                        _append_line(f"{indent_str}{key}: {val}")
                return
            if isinstance(value, (list, tuple)):
                if all(isinstance(item, str) for item in value):
                    for item in value:
                        if item:
                            _append_line(f"{indent_str}{item}")
                else:
                    for item in value:
                        _append_structured(item, indent)
                return
            _append_line(f"{indent_str}{value}")

        for ext_info in extensions:
            oid = ext_info.get("oid")
            friendly = ext_info.get("friendlyName")
            name = ext_info.get("name")
            include_oid = ext_info.get("includeOidInHeader", True)
            header_override = ext_info.get("displayHeader")

            if isinstance(header_override, str) and header_override.strip():
                header = header_override.strip()
            else:
                header_parts: List[str] = []
                if include_oid and oid:
                    header_parts.append(oid)
                display_name = friendly or (name if name and name != oid else None)
                if display_name:
                    if include_oid and header_parts:
                        header_parts.append(f"({display_name})")
                    else:
                        header_parts.append(display_name)
                if not header_parts:
                    fallback = name or friendly or oid or "Extension"
                    header_parts.append(fallback)
                header = " ".join(header_parts)

            if ext_info.get("critical"):
                header = f"{header} [critical]"
            _append_line(f"    {header}:")
            _append_structured(ext_info.get("value"), 2)

    if signature_lines:
        _append_blank_line()
        _append_line(f"Signature Algorithm: {signature_algorithm}")
        for line in signature_lines:
            _append_line(f"    {line}")

    fingerprint_order = ["md5", "sha1", "sha256"]
    if any(fingerprints.get(label) for label in fingerprint_order):
        _append_blank_line()
        _append_line("Fingerprint:")
        for label in fingerprint_order:
            hex_value = fingerprints.get(label)
            if not hex_value:
                continue
            colon_lines = format_hex_string_lines(hex_value)
            _append_line(f"    {label.upper()}:")
            for line in colon_lines:
                _append_line(f"        {line}")

    try:
        ski_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        ski_lines: List[str] = []
    else:
        ski_lines = format_hex_bytes_lines(ski_extension.value.digest)

    if ski_lines:
        _append_blank_line()
        _append_line("Subject Key Identifier:")
        for line in ski_lines:
            _append_line(f"    {line}")

    summary = "\n".join(line for line in summary_lines if line is not None).strip()

    signature_details = {
        "algorithm": signature_algorithm,
        "hash": signature_hash,
        "hex": signature_hex,
        "colon": signature_colon,
        "lines": signature_lines,
    }
    algorithm_info = _derive_certificate_algorithm_info(public_key_info, signature_details)
    subject_common_names = _extract_common_names(certificate.subject)

    return {
        "version": {
            "display": f"{version_number} ({version_hex})",
            "numeric": version_number,
            "hex": version_hex,
        },
        "serialNumber": {
            "decimal": str(certificate.serial_number),
            "hex": f"0x{certificate.serial_number:x}",
        },
        "signatureAlgorithm": signature_algorithm,
        "issuer": format_x509_name(certificate.issuer),
        "validity": {
            "notBefore": _isoformat(not_valid_before),
            "notAfter": _isoformat(not_valid_after),
        },
        "subject": format_x509_name(certificate.subject),
        "subjectCommonNames": subject_common_names,
        "publicKeyInfo": public_key_info,
        "algorithmInfo": algorithm_info,
        "extensions": extensions,
        "fingerprints": fingerprints,
        "signature": signature_details,
        "derBase64": der_base64,
        "pem": pem,
        "summary": summary,
    }


def _serialize_public_key_info(public_key):
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
        "algorithm": {
            "name": None,
        },
    }

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = getattr(public_key.curve, "name", "unknown")
        info.update(
            {
                "type": "ECC",
                "curve": curve_name,
                "uncompressedPoint": colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "ECDSA",
                "namedCurve": curve_name,
            }
        )
    elif isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        modulus_hex = f"0x{numbers.n:x}"
        key_size = getattr(public_key, "key_size", None)
        info.update(
            {
                "type": "RSA",
                "publicExponent": numbers.e,
                "modulusHex": modulus_hex,
            }
        )
        info["algorithm"].update(
            {
                "name": "RSASSA-PKCS1-v1_5",
                "modulusLength": key_size,
            }
        )
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info.update(
            {
                "type": public_key.__class__.__name__,
                "publicKeyHex": colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "EdDSA",
            }
        )

    if not info["algorithm"].get("name"):
        info["algorithm"]["name"] = info.get("type") or public_key.__class__.__name__

    return info


def _serialize_extension_value(ext):
    value = ext.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        hex_lines = format_hex_bytes_lines(value.digest)
        return {
            "Hex value": hex_lines if hex_lines else colon_hex(value.digest),
        }
    if isinstance(value, x509.AuthorityKeyIdentifier):
        serialized = {}
        if value.key_identifier:
            hex_lines = format_hex_bytes_lines(value.key_identifier)
            serialized["Hex value"] = hex_lines if hex_lines else colon_hex(value.key_identifier)
        if value.authority_cert_serial_number is not None:
            serialized["Authority Cert Serial Number"] = (
                f"{value.authority_cert_serial_number} "
                f"(0x{value.authority_cert_serial_number:x})"
            )
        if value.authority_cert_issuer:
            serialized["Authority Cert Issuer"] = [
                format_x509_name(name) for name in value.authority_cert_issuer
            ]
        return serialized
    if isinstance(value, x509.BasicConstraints):
        serialized = {"CA": "TRUE" if value.ca else "FALSE"}
        if value.path_length is not None:
            serialized["Path Length"] = value.path_length
        return serialized
    if isinstance(value, x509.UnrecognizedExtension):
        raw_bytes = value.value
        raw_hex = raw_bytes.hex()
        oid = ext.oid.dotted_string

        if oid == "1.3.6.1.4.1.45724.1.1.4":
            aaguid_bytes = decode_asn1_octet_string(raw_bytes)
            if len(aaguid_bytes) == 16:
                return {"AAGUID": aaguid_bytes.hex()}
            return {"Hex value": raw_hex}

        serialized: Dict[str, Any] = {"Hex value": raw_hex}
        if oid == "1.3.6.1.4.1.45724.2.1.1":
            transports = _parse_fido_transport_bitfield(raw_bytes)
            if transports:
                serialized["Transports"] = " ".join(transports)
        return serialized

    try:
        return str(value)
    except Exception:
        return repr(value)


def _parse_fido_transport_bitfield(raw_value: bytes):
    if not raw_value:
        return []

    data = raw_value
    if raw_value[0] == 0x03 and len(raw_value) >= 3:
        unused_bits = raw_value[2]
        data = raw_value[3: 3 + raw_value[1] - 1]
    else:
        unused_bits = 0

    aggregate = 0
    for byte in data:
        aggregate = (aggregate << 8) | byte

    if unused_bits:
        aggregate >>= unused_bits

    transport_map = [
        (0x01, "USB"),
        (0x02, "NFC"),
        (0x04, "BLE"),
        (0x08, "TEST"),
        (0x10, "INTERNAL"),
        (0x20, "USB-C"),
        (0x40, "LIGHTNING"),
        (0x80, "BT CLASSIC"),
    ]

    transports = [label for mask, label in transport_map if aggregate & mask]
    return transports


def perform_attestation_checks(
    response: Mapping[str, Any],
    state: Optional[Mapping[str, Any]],
    public_key_options: Optional[Mapping[str, Any]],
    auth_data: Optional[AuthenticatorData],
    expected_origin: str,
    rp_id: str,
) -> Dict[str, Any]:
    """Execute a comprehensive set of attestation validation checks."""

    results: Dict[str, Any] = {
        "attestation_format": None,
        "signature_valid": None,
        "root_valid": None,
        "rp_id_hash_valid": None,
        "aaguid_match": None,
        "client_data": {},
        "authenticator_data": {},
        "metadata": {},
        "hash_binding": {},
        "errors": [],
    }

    if not isinstance(response, Mapping):
        results["errors"].append("registration_response_invalid")
        return results

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:
        results["errors"].append(f"registration_parse_error: {exc}")
        return results

    client_data = registration.response.client_data
    attestation_object = registration.response.attestation_object
    results["attestation_format"] = attestation_object.fmt

    if isinstance(auth_data, AuthenticatorData):
        auth_data_obj = auth_data
    else:
        auth_data_obj = attestation_object.auth_data

    def _coerce_expected_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, ByteBuffer):
            return bytes(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            try:
                return websafe_decode(value)
            except Exception:
                pass
            try:
                padded = value + "=" * ((4 - len(value) % 4) % 4)
                return base64.b64decode(padded)
            except Exception:
                pass
            try:
                return bytes.fromhex(value)
            except Exception:
                pass
            return value.encode("utf-8")
        if isinstance(value, Mapping):
            if "$base64url" in value:
                return _coerce_expected_bytes(value["$base64url"])
            if "$base64" in value:
                encoded = value["$base64"]
                try:
                    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
                    return base64.b64decode(padded)
                except Exception:
                    return b""
            if "$hex" in value:
                try:
                    return bytes.fromhex(value["$hex"])
                except Exception:
                    return b""
        return b""

    expected_challenge_bytes = b""
    if isinstance(state, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(state.get("challenge"))
    if not expected_challenge_bytes and isinstance(public_key_options, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(
            public_key_options.get("challenge")
        )

    challenge_matches = (
        bool(expected_challenge_bytes)
        and client_data.challenge == expected_challenge_bytes
    )

    expected_origin_normalized = (expected_origin or "").rstrip("/")
    origin_matches = bool(expected_origin_normalized) and (
        client_data.origin == expected_origin_normalized
    )

    results["client_data"] = {
        "type": client_data.type,
        "expected_type": CollectedClientData.TYPE.CREATE.value,
        "type_valid": client_data.type
        == CollectedClientData.TYPE.CREATE.value,
        "challenge": encode_base64url(client_data.challenge),
        "expected_challenge": (
            encode_base64url(expected_challenge_bytes)
            if expected_challenge_bytes
            else None
        ),
        "challenge_matches": challenge_matches,
        "origin": client_data.origin,
        "expected_origin": expected_origin_normalized,
        "origin_valid": origin_matches,
        "cross_origin": bool(client_data.cross_origin),
        "cross_origin_ok": not bool(client_data.cross_origin),
    }

    if not results["client_data"]["type_valid"]:
        results["errors"].append("client_data_type_invalid")
    if expected_challenge_bytes and not challenge_matches:
        results["errors"].append("challenge_mismatch")
    if expected_origin_normalized and not origin_matches:
        results["errors"].append("origin_mismatch")
    if bool(client_data.cross_origin):
        results["errors"].append("cross_origin_not_allowed")

    rp_id_value = rp_id or ""
    rp_id_hash_expected = hashlib.sha256(rp_id_value.encode("utf-8")).digest()
    rp_id_hash_valid = auth_data_obj.rp_id_hash == rp_id_hash_expected
    results["rp_id_hash_valid"] = rp_id_hash_valid

    if not rp_id_hash_valid:
        results["errors"].append("rp_id_hash_mismatch")

    flags = auth_data_obj.flags
    user_present = bool(flags & AuthenticatorData.FLAG.UP)
    user_verified = bool(flags & AuthenticatorData.FLAG.UV)
    attested_credential_included = bool(flags & AuthenticatorData.FLAG.AT)

    uv_required = False
    if isinstance(state, Mapping):
        state_uv = state.get("user_verification")
        if getattr(state_uv, "value", None) == "required" or state_uv == "required":
            uv_required = True

    if not uv_required and isinstance(public_key_options, Mapping):
        uv_setting: Optional[str] = None
        authenticator_selection = public_key_options.get("authenticatorSelection")
        if isinstance(authenticator_selection, Mapping):
            uv_setting = authenticator_selection.get("userVerification")
        if not uv_setting:
            uv_setting = public_key_options.get("userVerification")
        if isinstance(uv_setting, str) and uv_setting.lower() == "required":
            uv_required = True

    uv_satisfied = user_verified or not uv_required

    if not user_present:
        results["errors"].append("user_presence_missing")
    if uv_required and not uv_satisfied:
        results["errors"].append("user_verification_required_not_satisfied")
    if not attested_credential_included:
        results["errors"].append("attested_credential_data_missing")

    allowed_algorithms: List[int] = []
    if isinstance(public_key_options, Mapping):
        params = public_key_options.get("pubKeyCredParams")
        if isinstance(params, list):
            for param in params:
                if isinstance(param, Mapping) and isinstance(param.get("alg"), int):
                    allowed_algorithms.append(param["alg"])

    credential_data = getattr(auth_data_obj, "credential_data", None)
    credential_id_length: Optional[int] = None
    credential_aaguid: Optional[str] = None
    credential_aaguid_bytes = b""
    algorithm: Optional[int] = None
    cose_key_valid = False

    if credential_data is not None:
        try:
            credential_id_length = len(credential_data.credential_id)
        except Exception:
            credential_id_length = None

        try:
            cose_map = dict(credential_data.public_key)
        except Exception:
            cose_map = {}

        try:
            if cose_map:
                algorithm = cose_map.get(3)
                CoseKey.parse(cose_map)
            else:
                algorithm = credential_data.public_key.get(3)
                CoseKey.parse(dict(credential_data.public_key))
            cose_key_valid = True
        except Exception as exc:
            if algorithm is None:
                try:
                    algorithm = credential_data.public_key.get(3)
                except Exception:
                    algorithm = None
            results["errors"].append(f"cose_key_error: {exc}")

        try:
            credential_aaguid_bytes = bytes(credential_data.aaguid)
            credential_aaguid = credential_aaguid_bytes.hex()
        except Exception:
            credential_aaguid_bytes = b""
            credential_aaguid = None

    algorithm_allowed = True
    if allowed_algorithms:
        if isinstance(algorithm, int):
            algorithm_allowed = algorithm in allowed_algorithms
        else:
            algorithm_allowed = False

    if allowed_algorithms and not algorithm_allowed:
        results["errors"].append("algorithm_not_allowed")

    results["authenticator_data"] = {
        "user_present": user_present,
        "user_verified": user_verified,
        "user_verification_required": uv_required,
        "user_verification_satisfied": uv_satisfied,
        "attested_credential_data": attested_credential_included,
        "counter": auth_data_obj.counter,
        "credential_id_length": credential_id_length,
        "credential_aaguid": credential_aaguid,
        "algorithm": algorithm,
        "algorithm_allowed": algorithm_allowed,
        "cose_key_valid": cose_key_valid,
    }

    client_data_hash = client_data.hash
    verification_data = bytes(auth_data_obj) + client_data_hash
    results["hash_binding"] = {
        "client_data_hash": encode_base64url(client_data_hash),
        "verification_data": encode_base64url(verification_data),
    }

    attestation_format_value = (attestation_object.fmt or "").lower()
    signature_valid: Optional[bool] = None
    attestation_result = None
    if attestation_format_value == "none":
        signature_valid = None
    else:
        try:
            attestation_cls = Attestation.for_type(attestation_object.fmt)
            attestation_instance = attestation_cls()
            attestation_result = attestation_instance.verify(
                attestation_object.att_stmt,
                attestation_object.auth_data,
                client_data_hash,
            )
            signature_valid = True
        except UnsupportedType as exc:
            results["errors"].append(f"unsupported_attestation: {exc}")
            signature_valid = False
        except (InvalidSignature, InvalidData) as exc:
            results["errors"].append(f"attestation_invalid: {exc}")
            signature_valid = False
        except Exception as exc:
            results["errors"].append(f"attestation_error: {exc}")
            signature_valid = False

    results["signature_valid"] = signature_valid

    metadata_entry = None
    now = datetime.now(timezone.utc)
    root_valid: Optional[bool] = None
    if signature_valid and attestation_result is not None:
        trust_path = attestation_result.trust_path or []
        if trust_path:
            certs_valid = True
            for cert_der in trust_path:
                try:
                    cert = x509.load_der_x509_certificate(cert_der)
                    not_before = _certificate_datetime(cert, "not_valid_before")
                    not_after = _certificate_datetime(cert, "not_valid_after")
                    if now < not_before or now > not_after:
                        certs_valid = False
                        results["errors"].append(
                            f"certificate_out_of_validity: {cert.subject.rfc4514_string()}"
                        )
                except Exception as exc:
                    certs_valid = False
                    results["errors"].append(f"certificate_parse_error: {exc}")
            if certs_valid:
                verifier = get_mds_verifier()
                if verifier is not None:
                    try:
                        metadata_entry = verifier.find_entry(
                            attestation_object,
                            client_data_hash,
                        )
                        if metadata_entry is not None:
                            root_valid = True
                        else:
                            root_valid = None
                            results["errors"].append("metadata_entry_not_found")
                    except Exception as exc:
                        results["errors"].append(f"untrusted_attestation: {exc}")
                        root_valid = False
                else:
                    results["errors"].append("metadata_not_available")
                    root_valid = None
            else:
                results["errors"].append("certificate_chain_invalid")
                root_valid = False
        else:
            results["errors"].append("trust_path_missing")
            root_valid = None
    elif signature_valid is False and attestation_format_value != "none":
        results["errors"].append("attestation_signature_invalid")
        root_valid = False

    metadata_description: Optional[str] = None
    metadata_aaguid: Optional[str] = None
    metadata_algorithm_supported: Optional[bool] = None
    metadata_aaguid_bytes = b""

    if metadata_entry is not None:
        metadata_statement = getattr(metadata_entry, "metadata_statement", None)
        if getattr(metadata_statement, "description", None):
            metadata_description = metadata_statement.description
        authenticator_info = getattr(
            metadata_statement,
            "authenticator_get_info",
            None,
        )
        algorithm = results["authenticator_data"].get("algorithm")
        if (
            isinstance(authenticator_info, Mapping)
            and isinstance(algorithm, int)
        ):
            alg_list = authenticator_info.get("algorithms")
            if isinstance(alg_list, (list, tuple)):
                numeric_algs = [alg for alg in alg_list if isinstance(alg, int)]
                if numeric_algs:
                    metadata_algorithm_supported = algorithm in numeric_algs
        entry_aaguid = getattr(metadata_entry, "aaguid", None)
        if entry_aaguid is not None:
            try:
                metadata_aaguid = str(entry_aaguid)
                metadata_aaguid_bytes = bytes(entry_aaguid)
                results["aaguid_match"] = (
                    metadata_aaguid_bytes == credential_aaguid_bytes
                )
            except Exception:
                pass

    if metadata_entry is None and credential_aaguid_bytes:
        if metadata_aaguid_bytes:
            results["aaguid_match"] = metadata_aaguid_bytes == credential_aaguid_bytes
        else:
            results["aaguid_match"] = False

    if results["aaguid_match"] is False and not credential_aaguid_bytes:
        results["aaguid_match"] = None

    if metadata_entry is None and not credential_aaguid_bytes:
        results["aaguid_match"] = None

    if results["aaguid_match"] is None and credential_aaguid_bytes and metadata_entry is not None:
        results["aaguid_match"] = metadata_aaguid_bytes == credential_aaguid_bytes

    results["metadata"] = {
        "available": metadata_entry is not None,
        "description": metadata_description,
        "aaguid": metadata_aaguid,
        "algorithm_supported": metadata_algorithm_supported,
    }

    if metadata_entry is not None and results["aaguid_match"] is False:
        results["errors"].append("aaguid_mismatch")
    if metadata_algorithm_supported is False:
        results["errors"].append("algorithm_not_in_metadata")

    if results["aaguid_match"] is False and metadata_entry is None:
        results["aaguid_match"] = None

    if root_valid is not None:
        results["root_valid"] = root_valid

    return results
