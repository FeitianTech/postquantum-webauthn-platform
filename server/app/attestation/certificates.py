from __future__ import annotations

import hashlib
import re
import textwrap
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from fido2.cose import (
    describe_mldsa_oid,
    describe_mldsa_oid_name,
    extract_certificate_public_key_info,
)
from fido2.utils import ByteBuffer
from fido2.webauthn import RegistrationResponse

from .. import encoding
from ..encoding import encode_base64
from . import formatting, trust
from .constants import EXTENSION_DISPLAY_METADATA

_HASH_NORMALISE_PATTERN = re.compile(r"sha-?(\d{3})$", re.IGNORECASE)


def format_x509_name(name: Any) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


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


def _normalise_signature_algorithm_name(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return ""

    lowered = text.lower()
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassa-pss" in lowered:
        return "RSASSA-PSS"
    if "rsa" in lowered:
        return "RSASSA-PKCS1-v1_5"
    if "ed25519" in lowered:
        return "ED25519"
    if "ed448" in lowered:
        return "ED448"
    if "dsa" in lowered:
        return "DSA"

    return text.replace("-", "").replace(" ", "").upper()


def _derive_certificate_algorithm_info(signature_info: Mapping[str, Any]) -> str:
    if not isinstance(signature_info, Mapping):
        return ""

    algorithm_component = ""
    raw_algorithm_name: Any = signature_info.get("algorithm")
    if isinstance(raw_algorithm_name, Mapping):
        raw_algorithm_name = raw_algorithm_name.get("name")
    if isinstance(raw_algorithm_name, str):
        algorithm_component = _normalise_signature_algorithm_name(raw_algorithm_name)

    hash_component = ""
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
        _format_algorithm_component(algorithm_component),
        _format_hash_value(hash_component),
    ):
        if part and (not components or part.lower() != components[-1].lower()):
            components.append(part)

    return "_".join(components)


def _extract_common_names(name: Any) -> list[str]:
    values: list[str] = []
    for attribute in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = attribute.value
        if isinstance(value, str):
            text = value.strip()
            if text:
                values.append(text)
    return values


def _build_unknown_public_key_info(cert_bytes: bytes, error: Exception) -> tuple[dict[str, Any], list[tuple[str, Any]]]:
    try:
        parsed = extract_certificate_public_key_info(cert_bytes)
    except Exception:
        parsed = {}

    algorithm_details: dict[str, Any] = {"name": "Unknown"}
    public_key_bytes = parsed.get("subject_public_key")
    wrapped_public_key_bytes = parsed.get("wrapped_subject_public_key")
    spki_bytes = parsed.get("subject_public_key_info")

    if isinstance(parsed.get("algorithm_name"), str):
        algorithm_details["name"] = parsed["algorithm_name"]
    if isinstance(parsed.get("algorithm_oid"), str):
        algorithm_details["oid"] = parsed["algorithm_oid"]

    mldsa_details: Mapping[str, Any] | None = None
    parameter_set = parsed.get("ml_dsa_parameter_set")
    if isinstance(parameter_set, str):
        algorithm_details["mlDsaParameterSet"] = parameter_set
        candidate = parsed.get("ml_dsa_parameter_details")
        if isinstance(candidate, Mapping):
            mldsa_details = candidate
            claimed_level = candidate.get("claimed_nist_level")
            if claimed_level is not None:
                algorithm_details["claimedNistLevel"] = claimed_level
            length_signature = candidate.get("signature_length")
            if isinstance(length_signature, int):
                algorithm_details["signatureLengthBytes"] = length_signature
    parameters = parsed.get("algorithm_parameters")
    if isinstance(parameters, (bytes, bytearray)) and parameters:
        algorithm_details["parametersHex"] = bytes(parameters).hex()

    info: dict[str, Any] = {
        "type": algorithm_details.get("name", "Unsupported"),
        "algorithm": algorithm_details,
    }

    if isinstance(spki_bytes, (bytes, bytearray)) and spki_bytes:
        info["subjectPublicKeyInfoBase64"] = encode_base64(bytes(spki_bytes))

    key_size_bits: int | None = None
    raw_bytes: bytes | None = None
    if isinstance(public_key_bytes, (bytes, bytearray)):
        candidate = bytes(public_key_bytes)
        if candidate:
            raw_bytes = candidate
            info["publicKeyBase64"] = encode_base64(raw_bytes)
            info["publicKeyHex"] = formatting.colon_hex(raw_bytes)
            info["publicKeyHexLines"] = formatting.format_hex_bytes_lines(raw_bytes)
            key_size_bits = len(raw_bytes) * 8

    if isinstance(wrapped_public_key_bytes, (bytes, bytearray)):
        wrapped_bytes = bytes(wrapped_public_key_bytes)
        if wrapped_bytes and (raw_bytes is None or wrapped_bytes != raw_bytes):
            info["wrappedPublicKeyBase64"] = encode_base64(wrapped_bytes)
            info["wrappedPublicKeyHexLines"] = formatting.format_hex_bytes_lines(wrapped_bytes)

    if isinstance(mldsa_details, Mapping):
        length_public_key = mldsa_details.get("public_key_length")
        if isinstance(length_public_key, int) and length_public_key > 0:
            key_size_bits = length_public_key * 8
        info["mechanismName"] = parameter_set
        info["mechanismFamily"] = "ML-DSA"

    if key_size_bits:
        info["keySize"] = key_size_bits

    summary_entries: list[tuple[str, Any]] = []

    def _append_summary(label: str, value: Any) -> None:
        if value in (None, ""):
            return
        if isinstance(value, list) and not value:
            return
        summary_entries.append((label, value))

    _append_summary("Type", info.get("type"))
    algorithm_name = algorithm_details.get("name")
    if algorithm_name and algorithm_name != info.get("type"):
        _append_summary("Algorithm", algorithm_name)
    _append_summary("Algorithm OID", algorithm_details.get("oid"))
    _append_summary("ML-DSA parameter set", algorithm_details.get("mlDsaParameterSet"))
    _append_summary("Claimed NIST level", algorithm_details.get("claimedNistLevel"))
    _append_summary("Signature length (bytes)", algorithm_details.get("signatureLengthBytes"))
    if key_size_bits:
        _append_summary("Public key size (bits)", key_size_bits)
    _append_summary("Public Key (base64)", info.get("publicKeyBase64"))
    hex_lines = info.get("publicKeyHexLines")
    if isinstance(hex_lines, list) and hex_lines:
        _append_summary("Public Key (hex)", hex_lines)
    wrapped_hex_lines = info.get("wrappedPublicKeyHexLines")
    if isinstance(wrapped_hex_lines, list) and wrapped_hex_lines:
        _append_summary("Wrapped Public Key (hex)", wrapped_hex_lines)

    if not summary_entries and "error" not in info:
        info["error"] = str(error)
        summary_entries.append(("Error", str(error)))

    return info, summary_entries


def _serialize_public_key_info(public_key: Any) -> dict[str, Any]:
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": encode_base64(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
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
                "uncompressedPoint": formatting.colon_hex(
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
                "publicKeyHex": formatting.colon_hex(
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


def _parse_fido_transport_bitfield(raw_value: bytes) -> list[str]:
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


def _serialize_extension_value(ext: Any) -> Any:
    value = ext.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        hex_lines = formatting.format_hex_bytes_lines(value.digest)
        return {
            "Hex value": hex_lines if hex_lines else formatting.colon_hex(value.digest),
        }
    if isinstance(value, x509.AuthorityKeyIdentifier):
        serialized: dict[str, Any] = {}
        if value.key_identifier:
            hex_lines = formatting.format_hex_bytes_lines(value.key_identifier)
            serialized["Hex value"] = hex_lines if hex_lines else formatting.colon_hex(value.key_identifier)
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

        if oid == "1.3.6.1.4.1.41482.13.1":
            version_bytes = formatting.decode_asn1_octet_string(raw_bytes)
            if version_bytes:
                version_components = "".join(
                    f"{byte}." for byte in version_bytes
                ).strip(".")
                if version_components:
                    return {"Firmware version": version_components}
            return {"Hex value": raw_hex}

        if oid == "1.3.6.1.4.1.41482.2":
            identifier_bytes = formatting.decode_asn1_octet_string(raw_bytes)
            text_value: str | None
            try:
                text_value = identifier_bytes.decode("ascii").strip()
            except Exception:  # pragma: no cover - defensive
                text_value = None

            payload: dict[str, Any] = {"Hex value": raw_hex}
            if text_value:
                payload["Device identifier"] = text_value
            return payload

        if oid == "1.3.6.1.4.1.41482.1.1":
            identifier_bytes = formatting.decode_asn1_octet_string(raw_bytes)
            try:
                identifier_text = identifier_bytes.decode("ascii").strip()
            except Exception:  # pragma: no cover - defensive
                identifier_text = None

            if identifier_text:
                return {"Value": identifier_text}
            return {"Hex value": raw_hex}

        if oid == "1.3.6.1.4.1.45724.1.1.4":
            aaguid_bytes = formatting.decode_asn1_octet_string(raw_bytes)
            if len(aaguid_bytes) == 16:
                return {"AAGUID": aaguid_bytes.hex()}
            return {"Hex value": raw_hex}

        serialized = {"Hex value": raw_hex}
        if oid == "1.3.6.1.4.1.45724.2.1.1":
            transports = _parse_fido_transport_bitfield(raw_bytes)
            if transports:
                serialized["Transports"] = " ".join(transports)
        return serialized

    try:
        return str(value)
    except Exception:
        return repr(value)


def _build_certificate_summary(
    certificate: Any,
    *,
    version_number: int,
    version_hex: str,
    serial_decimal: str,
    serial_hex: str,
    signature_algorithm: str,
    not_valid_before: datetime,
    not_valid_after: datetime,
    public_key: Any,
    fallback_public_key_summary: Sequence[tuple[str, Any]],
    extensions: Sequence[Mapping[str, Any]],
    signature_lines: Sequence[str],
    fingerprints: Mapping[str, str],
) -> str:
    summary_lines: list[str] = []

    def _append_line(line: str) -> None:
        summary_lines.append(line)

    def _append_blank_line() -> None:
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")

    def _isoformat(value: datetime) -> str:
        return trust._ensure_utc_datetime(value).isoformat()

    _append_line(f"Version: {version_number} ({version_hex})")
    _append_line(
        f"Certificate Serial Number: {serial_decimal} ({serial_hex})"
    )
    _append_line(f"Signature Algorithm: {signature_algorithm}")
    _append_line(f"Issuer: {format_x509_name(certificate.issuer)}")

    _append_blank_line()
    _append_line("Validity:")
    _append_line(f"    Not Before: {_isoformat(not_valid_before)}")
    _append_line(f"    Not After: {_isoformat(not_valid_after)}")

    _append_blank_line()
    _append_line(f"Subject: {format_x509_name(certificate.subject)}")

    pk_summary_entries: list[tuple[str, Any]] = []
    if public_key is None:
        pk_summary_entries.extend(fallback_public_key_summary)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        pk_summary_entries.append(("Type", "ECC"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        ecc_point_lines = formatting.format_hex_bytes_lines(
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
        modulus_lines = formatting.format_hex_bytes_lines(modulus_bytes)
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
        raw_lines = formatting.format_hex_bytes_lines(raw_bytes)
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
                header_parts: list[str] = []
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
            colon_lines = formatting.format_hex_string_lines(hex_value)
            _append_line(f"    {label.upper()}:")
            for line in colon_lines:
                _append_line(f"        {line}")

    try:
        ski_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        ski_lines: list[str] = []
    else:
        ski_lines = formatting.format_hex_bytes_lines(ski_extension.value.digest)

    if ski_lines:
        _append_blank_line()
        _append_line("Subject Key Identifier:")
        for line in ski_lines:
            _append_line(f"    {line}")

    return "\n".join(line for line in summary_lines if line is not None).strip()


def _serialize_attestation_certificate_fallback(
    cert_bytes: bytes, error: Exception
) -> dict[str, Any]:
    """Return certificate metadata when DER parsing fails."""

    der_base64 = encode_base64(cert_bytes)
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    fingerprints = {
        "sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "sha1": hashlib.sha1(cert_bytes).hexdigest(),
        "md5": hashlib.md5(cert_bytes).hexdigest(),
    }

    public_key_info, summary_entries = _build_unknown_public_key_info(cert_bytes, error)

    summary_lines = [
        "Unable to parse attestation certificate using cryptography.x509.",
        f"Error: {error}",
        "",
        f"DER length: {len(cert_bytes)} bytes",
        "",
        "Fingerprints:",
        f"    SHA256: {fingerprints['sha256']}",
        f"    SHA1: {fingerprints['sha1']}",
        f"    MD5: {fingerprints['md5']}",
    ]

    if summary_entries:
        summary_lines.append("")
        summary_lines.append("Best-effort public key details:")
        for label, value in summary_entries:
            if value in (None, ""):
                continue
            if isinstance(value, list):
                summary_lines.append(f"    {label}:")
                for item in value:
                    summary_lines.append(f"        {item}")
            else:
                summary_lines.append(f"    {label}: {value}")

    summary = "\n".join(summary_lines).strip()

    return {
        "error": f"Unable to parse attestation certificate: {error}",
        "derBase64": der_base64,
        "fingerprints": fingerprints,
        "pem": pem,
        "publicKeyInfo": public_key_info,
        "raw": cert_bytes.hex(),
        "summary": summary,
        "parseError": str(error),
    }


def serialize_attestation_certificate(cert_bytes: bytes) -> Any:
    if not cert_bytes:
        return None

    try:
        certificate = x509.load_der_x509_certificate(cert_bytes)
    except Exception as exc:  # pragma: no cover - exercised in dedicated tests
        return _serialize_attestation_certificate_fallback(cert_bytes, exc)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    not_valid_before = trust._certificate_datetime(certificate, "not_valid_before")
    not_valid_after = trust._certificate_datetime(certificate, "not_valid_after")

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
    der_base64 = encode_base64(der_bytes)
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    signature_algorithm_oid = getattr(
        certificate.signature_algorithm_oid,
        "dotted_string",
        None,
    )
    raw_signature_algorithm = getattr(
        certificate.signature_algorithm_oid,
        "_name",
        signature_algorithm_oid,
    )
    if isinstance(raw_signature_algorithm, str) and raw_signature_algorithm.lower() == "unknown oid":
        signature_algorithm = signature_algorithm_oid or raw_signature_algorithm
    else:
        signature_algorithm = raw_signature_algorithm

    signature_algorithm_details = describe_mldsa_oid(signature_algorithm_oid)
    friendly_signature_name = describe_mldsa_oid_name(signature_algorithm_oid)
    if friendly_signature_name:
        signature_algorithm = friendly_signature_name

    fallback_public_key_summary = []
    try:
        public_key = certificate.public_key()
    except (UnsupportedAlgorithm, ValueError) as exc:
        public_key = None
        public_key_info, fallback_public_key_summary = _build_unknown_public_key_info(cert_bytes, exc)
    else:
        public_key_info = _serialize_public_key_info(public_key)

    signature_bytes = certificate.signature
    signature_lines = formatting.format_hex_bytes_lines(signature_bytes)
    signature_hex = signature_bytes.hex()
    signature_colon = formatting.colon_hex(signature_bytes)

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

    summary = _build_certificate_summary(
        certificate,
        version_number=version_number,
        version_hex=version_hex,
        serial_decimal=serial_decimal,
        serial_hex=serial_hex,
        signature_algorithm=signature_algorithm,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        public_key=public_key,
        fallback_public_key_summary=fallback_public_key_summary,
        extensions=extensions,
        signature_lines=signature_lines,
        fingerprints=fingerprints,
    )

    signature_details = {
        "algorithm": signature_algorithm,
        "hash": signature_hash,
        "hex": signature_hex,
        "colon": signature_colon,
        "lines": signature_lines,
        "oid": signature_algorithm_oid,
        "details": signature_algorithm_details,
    }
    algorithm_info = _derive_certificate_algorithm_info(signature_details)
    subject_common_names = _extract_common_names(certificate.subject)

    def _isoformat(value: datetime) -> str:
        return trust._ensure_utc_datetime(value).isoformat()

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
        "signatureAlgorithmOid": signature_algorithm_oid,
        "signatureAlgorithmDetails": signature_algorithm_details,
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


def _coerce_attestation_certificate_bytes(value: Any) -> bytes | None:
    """Return raw certificate bytes for attestation payload *value*."""

    if value in (None, ""):
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, ByteBuffer):
        return value.getvalue()

    if isinstance(value, str):
        if not value.strip():
            return None
        decoded = encoding.try_decode_base64(value)
        if decoded is None:
            decoded = encoding.try_decode_base64url(value)
        return decoded

    if isinstance(value, Mapping):
        raw_value = value.get("raw")
        if isinstance(raw_value, str):
            decoded = encoding.try_decode_hex(raw_value)
            if decoded is not None:
                return decoded

        der_base64 = value.get("derBase64") or value.get("der_base64")
        if isinstance(der_base64, str):
            decoded = encoding.try_decode_base64(der_base64)
            if decoded is not None:
                return decoded

        pem_value = value.get("pem")
        if isinstance(pem_value, str):
            try:
                return encoding.decode_pem_body(pem_value)
            except encoding.EncodingError:
                pass

    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def extract_attestation_details(
    response: Any,
) -> tuple[
    str,
    dict[str, Any],
    str | None,
    str | None,
    dict[str, Any],
    dict[str, Any] | None,
    list[dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""
    attestation_format = "none"
    attestation_statement: dict[str, Any] = {}
    attestation_object_b64: str | None = None
    client_data_b64: str | None = None
    client_extension_results: dict[str, Any] = {}
    attestation_certificate: dict[str, Any] | None = None
    attestation_certificates: list[dict[str, Any]] = []

    if not isinstance(response, dict):
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
            attestation_certificates,
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
            attestation_certificates,
        )

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = formatting.encode_base64url(bytes(attestation_object))

    if isinstance(attestation_statement, Mapping):
        cert_chain = attestation_statement.get("x5c") or []
        if isinstance(cert_chain, (list, tuple)) and cert_chain:
            for entry in cert_chain:
                certificate_bytes = _coerce_attestation_certificate_bytes(entry)
                if certificate_bytes is None:
                    attestation_certificates.append({
                        "error": "Unable to decode attestation certificate bytes.",
                    })
                    continue

                try:
                    certificate_details = serialize_attestation_certificate(certificate_bytes)
                except Exception as cert_error:  # pragma: no cover - defensive
                    certificate_details = {"error": str(cert_error)}
                else:
                    if certificate_details is None:
                        certificate_details = {
                            "error": "Unable to parse attestation certificate.",
                        }

                attestation_certificates.append(certificate_details)

            if attestation_certificates:
                attestation_certificate = attestation_certificates[0]

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = formatting.encode_base64url(bytes(client_data))

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
        attestation_certificates,
    )
