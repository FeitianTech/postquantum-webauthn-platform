"""``webauthn.attestation.certificate_extensions``: how the certificate views show an extension's value.

``certificates`` hands each extension to ``_serialize_extension_value``; these give it
cryptography's own extension values.
"""
from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)

FIRMWARE = "1.3.6.1.4.1.41482.13.1"
DEVICE_IDENTIFIER = "1.3.6.1.4.1.41482.2"
YUBICO_IDENTIFIER = "1.3.6.1.4.1.41482.1.1"
AAGUID = "1.3.6.1.4.1.45724.1.1.4"
TRANSPORTS = "1.3.6.1.4.1.45724.2.1.1"


def _shown(oid: str, value) -> object:
    return attestation_certificate_extensions._serialize_extension_value(SimpleNamespace(oid=ObjectIdentifier(oid), value=value))


def _unrecognized(oid: str, raw: bytes) -> object:
    return _shown(oid, x509.UnrecognizedExtension(ObjectIdentifier(oid), raw))


def test_an_authority_key_identifier_shows_its_key_serial_and_issuer():
    issuer = x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo Issuer")]))
    value = x509.AuthorityKeyIdentifier(key_identifier=b"\x01\x02", authority_cert_issuer=[issuer], authority_cert_serial_number=17)

    shown = _shown("2.5.29.35", value)

    assert shown["Hex value"] == ["01:02"]
    assert shown["Authority Cert Serial Number"] == "17 (0x11)"
    assert shown["Authority Cert Issuer"] == ["DirName:CN=Demo Issuer"]


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        (x509.DNSName("authenticator.example"), "DNS:authenticator.example"),
        (x509.RFC822Name("ca@example.com"), "email:ca@example.com"),
        (x509.UniformResourceIdentifier("http://ca.example/ca.crt"), "URI:http://ca.example/ca.crt"),
        (x509.IPAddress(ipaddress.ip_address("192.0.2.1")), "IP Address:192.0.2.1"),
        (x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA")])), "DirName:CN=Demo CA"),
        (x509.RegisteredID(ObjectIdentifier("1.2.3.4")), "Registered ID:1.2.3.4"),
        (x509.OtherName(ObjectIdentifier("2.23.133.2.1"), b"\x0c\x02id"), "othername:2.23.133.2.1:0c026964"),
    ],
)
def test_a_general_name_is_shown_with_its_kind_as_openssl_writes_it(name, shown):
    assert attestation_certificate_extensions._general_name(name) == shown


def test_an_authority_key_identifier_without_a_key_shows_what_it_has():
    value = x509.AuthorityKeyIdentifier(key_identifier=None, authority_cert_issuer=None, authority_cert_serial_number=None)

    assert _shown("2.5.29.35", value) == {}


def test_basic_constraints_show_the_ca_flag_and_its_path_length():
    assert _shown("2.5.29.19", x509.BasicConstraints(ca=True, path_length=0)) == {"CA": "TRUE", "Path Length": 0}


def _key_usage(**chosen: bool) -> x509.KeyUsage:
    usages = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    return x509.KeyUsage(**{**usages, **chosen})


@pytest.mark.parametrize(
    ("usage", "shown"),
    [
        (_key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True), "Digital Signature, Certificate Sign, CRL Sign"),
        (_key_usage(content_commitment=True, key_encipherment=True, data_encipherment=True), "Non Repudiation, Key Encipherment, Data Encipherment"),
        (_key_usage(key_agreement=True, encipher_only=True), "Key Agreement, Encipher Only"),
        (_key_usage(key_agreement=True, decipher_only=True), "Key Agreement, Decipher Only"),
    ],
)
def test_key_usage_names_each_usage_in_openssl_words(usage, shown):
    assert _shown("2.5.29.15", usage) == shown


@pytest.mark.parametrize(
    ("oid", "raw", "shown"),
    [
        (FIRMWARE, b"\x04\x03\x05\x04\x03", {"Firmware version": "5.4.3"}),
        (FIRMWARE, b"\x04\x00", {"Hex value": "0400"}),
        (DEVICE_IDENTIFIER, b"\x04\x02  ", {"Hex value": "04022020"}),
        (YUBICO_IDENTIFIER, b"\x04\x04demo", {"Value": "demo"}),
        (YUBICO_IDENTIFIER, b"\x04\x02  ", {"Hex value": "04022020"}),
        (AAGUID, b"\x04\x02\xaa\xbb", {"Hex value": "0402aabb"}),
        # FIDO's transports with no bit set name none.
        (TRANSPORTS, bytes.fromhex("030100"), {"Hex value": "030100"}),
    ],
)
def test_an_extension_that_says_nothing_readable_is_shown_as_hex(oid, raw, shown):
    assert _unrecognized(oid, raw) == shown


def test_an_extension_value_that_cannot_be_a_string_is_shown_as_its_repr():
    class ValueWithoutStr:
        def __str__(self):
            raise RuntimeError("cannot stringify")

        def __repr__(self):
            return "<a value>"

    assert _shown("1.2.3", ValueWithoutStr()) == "<a value>"
