from __future__ import annotations

from typing import Any, Dict, List, Optional


def _parse_fido_transport_bitfield(raw_value: bytes) -> List[str]:
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
        hex_lines = format_hex_bytes_lines(value.digest)
        return {
            "Hex value": hex_lines if hex_lines else colon_hex(value.digest),
        }
    if isinstance(value, x509.AuthorityKeyIdentifier):
        serialized: Dict[str, Any] = {}
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

        if oid == "1.3.6.1.4.1.41482.13.1":
            version_bytes = decode_asn1_octet_string(raw_bytes)
            if version_bytes:
                version_components = "".join(
                    f"{byte}." for byte in version_bytes
                ).strip(".")
                if version_components:
                    return {"Firmware version": version_components}
            return {"Hex value": raw_hex}

        if oid == "1.3.6.1.4.1.41482.2":
            identifier_bytes = decode_asn1_octet_string(raw_bytes)
            text_value: Optional[str]
            try:
                text_value = identifier_bytes.decode("ascii").strip()
            except Exception:  # pragma: no cover - defensive
                text_value = None

            payload: Dict[str, Any] = {"Hex value": raw_hex}
            if text_value:
                payload["Device identifier"] = text_value
            return payload

        if oid == "1.3.6.1.4.1.41482.1.1":
            identifier_bytes = decode_asn1_octet_string(raw_bytes)
            try:
                identifier_text = identifier_bytes.decode("ascii").strip()
            except Exception:  # pragma: no cover - defensive
                identifier_text = None

            if identifier_text:
                return {"Value": identifier_text}
            return {"Hex value": raw_hex}

        if oid == "1.3.6.1.4.1.45724.1.1.4":
            aaguid_bytes = decode_asn1_octet_string(raw_bytes)
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
