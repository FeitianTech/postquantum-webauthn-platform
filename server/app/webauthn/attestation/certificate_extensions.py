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
from cryptography.hazmat import asn1

from . import formatting

# id-fido-gen-ce-transports is a BIT STRING with named bits, bit 0 the first
# byte's most significant: bluetoothRadio, bluetoothLowEnergyRadio, uSB, nFC,
# uSBInternal (FIDO Authenticator Transports Extension).
_FIDO_TRANSPORT_BITS = ("BT CLASSIC", "BLE", "USB", "NFC", "USB INTERNAL")


def _parse_fido_transport_bitfield(raw_value: bytes) -> list[str] | None:
    """The transports the extension names; ``None`` when it is not a DER BIT STRING."""

    try:
        bits = asn1.decode_der(asn1.BitString, raw_value)
    except ValueError:
        return None
    data = bits.as_bytes()
    transports = []
    for index in range(len(data) * 8 - bits.padding_bits()):
        if data[index // 8] & (0x80 >> (index % 8)):
            known = index < len(_FIDO_TRANSPORT_BITS)
            transports.append(_FIDO_TRANSPORT_BITS[index] if known else f"bit {index}")
    return transports


def _key_identifier_value(digest: bytes) -> dict[str, Any]:
    hex_lines = formatting.format_hex_bytes_lines(digest)
    return {
        "Hex value": hex_lines if hex_lines else digest.hex(":"),
    }


# OpenSSL's word for each kind of general name (RFC 5280, 4.2.1.6) whose value is text.
_GENERAL_NAME_KINDS: dict[type, str] = {
    x509.DNSName: "DNS",
    x509.RFC822Name: "email",
    x509.UniformResourceIdentifier: "URI",
    x509.IPAddress: "IP Address",
}


def _general_name(name: x509.GeneralName) -> str:
    """A general name as OpenSSL writes it: its kind, a colon, its value."""

    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name.value.rfc4514_string()}"
    if isinstance(name, x509.RegisteredID):
        return f"Registered ID:{name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        return f"othername:{name.type_id.dotted_string}:{name.value.hex()}"
    return f"{_GENERAL_NAME_KINDS[type(name)]}:{name.value}"


def _authority_key_identifier_value(value: x509.AuthorityKeyIdentifier) -> dict[str, Any]:
    serialized: dict[str, Any] = {}
    if value.key_identifier:
        hex_lines = formatting.format_hex_bytes_lines(value.key_identifier)
        serialized["Hex value"] = hex_lines if hex_lines else value.key_identifier.hex(":")
    if value.authority_cert_serial_number is not None:
        serialized["Authority Cert Serial Number"] = (
            f"{value.authority_cert_serial_number} "
            f"(0x{value.authority_cert_serial_number:x})"
        )
    if value.authority_cert_issuer:
        serialized["Authority Cert Issuer"] = [_general_name(name) for name in value.authority_cert_issuer]
    return serialized


# OpenSSL's names for the key usage bits, in their order (RFC 5280, 4.2.1.3).
_KEY_USAGES = (
    ("digital_signature", "Digital Signature"),
    ("content_commitment", "Non Repudiation"),
    ("key_encipherment", "Key Encipherment"),
    ("data_encipherment", "Data Encipherment"),
    ("key_agreement", "Key Agreement"),
    ("key_cert_sign", "Certificate Sign"),
    ("crl_sign", "CRL Sign"),
)


def _key_usage_value(value: x509.KeyUsage) -> str:
    """The usages the key is for, in OpenSSL's words; encipher and decipher only qualify key agreement."""

    usages = [label for attribute, label in _KEY_USAGES if getattr(value, attribute)]
    if value.key_agreement:
        if value.encipher_only:
            usages.append("Encipher Only")
        if value.decipher_only:
            usages.append("Decipher Only")
    return ", ".join(usages)


def _oid_text(oid: x509.ObjectIdentifier) -> str:
    """An OID as cryptography's name for it with its number, or the number when it has no name."""

    name = oid._name
    return oid.dotted_string if name == "Unknown OID" else f"{name} ({oid.dotted_string})"


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

    version_bytes = formatting.der_octet_string_content(raw_bytes)
    if version_bytes:
        version_components = "".join(
            f"{byte}." for byte in version_bytes
        ).strip(".")
        if version_components:
            return {"Firmware version": version_components}
    return {"Hex value": raw_hex}


def _device_identifier_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """Yubico's 1.3.6.1.4.1.41482.2: the device identifier, as ASCII."""

    identifier_bytes = formatting.der_octet_string_content(raw_bytes)
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

    identifier_bytes = formatting.der_octet_string_content(raw_bytes)
    try:
        identifier_text = identifier_bytes.decode("ascii").strip()
    except Exception:  # pragma: no cover - defensive
        identifier_text = None

    if identifier_text:
        return {"Value": identifier_text}
    return {"Hex value": raw_hex}


def _aaguid_value(raw_bytes: bytes, raw_hex: str) -> dict[str, Any]:
    """FIDO's id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4)."""

    aaguid_bytes = formatting.der_octet_string_content(raw_bytes)
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
    if isinstance(value, x509.KeyUsage):
        return _key_usage_value(value)
    if isinstance(value, x509.ExtendedKeyUsage):
        return [_oid_text(purpose) for purpose in value]
    if isinstance(value, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        return [_general_name(name) for name in value]
    if isinstance(value, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
        return _signed_certificate_timestamps_value(value)
    if isinstance(value, x509.UnrecognizedExtension):
        return _unrecognized_extension_value(ext.oid.dotted_string, value.value)

    try:
        return str(value)
    except Exception:
        return repr(value)
