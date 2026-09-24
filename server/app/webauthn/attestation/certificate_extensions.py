"""How the certificate views show an X.509 extension's value.

Key identifiers, basic constraints, signed certificate timestamps and the FIDO
and Yubico extensions (AAGUID, transports, firmware version, device identifiers)
get a structured value; any other extension shows ``str()`` of cryptography's
parsed value.
"""
from __future__ import annotations

import datetime
from typing import Any

from cryptography import x509

from . import certificate_names, formatting


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


def _key_identifier_value(digest: bytes) -> dict[str, Any]:
    hex_lines = formatting.format_hex_bytes_lines(digest)
    return {
        "Hex value": hex_lines if hex_lines else formatting.colon_hex(digest),
    }


def _authority_key_identifier_value(value: x509.AuthorityKeyIdentifier) -> dict[str, Any]:
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
            certificate_names.format_x509_name(name) for name in value.authority_cert_issuer
        ]
    return serialized


def _basic_constraints_value(value: x509.BasicConstraints) -> dict[str, Any]:
    serialized: dict[str, Any] = {"CA": "TRUE" if value.ca else "FALSE"}
    if value.path_length is not None:
        serialized["Path Length"] = value.path_length
    return serialized


def _signed_certificate_timestamps_value(scts: Any) -> list[dict[str, Any]]:
    """RFC 6962 SCTs, one record each; ``str()`` of these names each object's memory address."""

    records = []
    for sct in scts:
        # cryptography gives a naive datetime that is in UTC.
        timestamp = sct.timestamp.replace(tzinfo=datetime.timezone.utc)
        records.append(
            {
                "Version": sct.version.name,
                "Log ID": sct.log_id.hex(),
                "Timestamp": timestamp.isoformat(timespec="milliseconds"),
                "Entry type": sct.entry_type.name,
                "Signature hash algorithm": sct.signature_hash_algorithm.name,
                "Signature algorithm": sct.signature_algorithm.name,
            }
        )
    return records


def _firmware_version_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """Yubico's 1.3.6.1.4.1.41482.13.1: the firmware version, one byte per component."""

    version_bytes = formatting.decode_asn1_octet_string(raw_bytes)
    if version_bytes:
        version_components = "".join(
            f"{byte}." for byte in version_bytes
        ).strip(".")
        if version_components:
            return {"Firmware version": version_components}
    return {"Hex value": raw_hex}


def _device_identifier_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """Yubico's 1.3.6.1.4.1.41482.2: the device identifier, as ASCII."""

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


def _yubico_identifier_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """Yubico's 1.3.6.1.4.1.41482.1.1: an ASCII identifier."""

    identifier_bytes = formatting.decode_asn1_octet_string(raw_bytes)
    try:
        identifier_text = identifier_bytes.decode("ascii").strip()
    except Exception:  # pragma: no cover - defensive
        identifier_text = None

    if identifier_text:
        return {"Value": identifier_text}
    return {"Hex value": raw_hex}


def _aaguid_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """FIDO's id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4)."""

    aaguid_bytes = formatting.decode_asn1_octet_string(raw_bytes)
    if len(aaguid_bytes) == 16:
        return {"AAGUID": aaguid_bytes.hex()}
    return {"Hex value": raw_hex}


def _unrecognized_extension_value(oid: str, raw_bytes: bytes) -> dict[str, Any]:
    """An extension cryptography does not parse: the FIDO and Yubico ones decoded, any other as hex."""

    raw_hex = raw_bytes.hex()
    if oid == "1.3.6.1.4.1.41482.13.1":
        return _firmware_version_value(raw_bytes, raw_hex)
    if oid == "1.3.6.1.4.1.41482.2":
        return _device_identifier_value(raw_bytes, raw_hex)
    if oid == "1.3.6.1.4.1.41482.1.1":
        return _yubico_identifier_value(raw_bytes, raw_hex)
    if oid == "1.3.6.1.4.1.45724.1.1.4":
        return _aaguid_value(raw_bytes, raw_hex)

    serialized = {"Hex value": raw_hex}
    if oid == "1.3.6.1.4.1.45724.2.1.1":
        transports = _parse_fido_transport_bitfield(raw_bytes)
        if transports:
            serialized["Transports"] = " ".join(transports)
    return serialized


def _serialize_extension_value(ext: Any) -> Any:
    value = ext.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        return _key_identifier_value(value.digest)
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return _authority_key_identifier_value(value)
    if isinstance(value, x509.BasicConstraints):
        return _basic_constraints_value(value)
    if isinstance(value, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
        return _signed_certificate_timestamps_value(value)
    if isinstance(value, x509.UnrecognizedExtension):
        return _unrecognized_extension_value(ext.oid.dotted_string, value.value)

    try:
        return str(value)
    except Exception:
        return repr(value)
