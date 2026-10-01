import base64
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
from fido2.utils import ByteBuffer

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)
from server.app.webauthn.attestation import certificates as attestation_certificates
from server.app.webauthn.attestation import trust as attestation_trust
from tests.app.entry_app import entry_app


def _self_signed_cert_der() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=10))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_collect_trust_path_entries_and_certificate_bytes_coercion_helpers():
    trust_path = attestation_trust._collect_trust_path_entries(
        [b"leaf", bytearray(b"intermediate"), "ignored", ByteBuffer(b"root")]
    )
    assert trust_path == [b"leaf", b"intermediate", b"root"]

    cert_bytes = b"\x30\x82\x01\x00"
    cert_b64 = base64.b64encode(cert_bytes).decode("ascii")

    assert attestation_trust._coerce_certificate_bytes(cert_b64) == cert_bytes
    assert attestation_trust._coerce_certificate_bytes("   ") is None


def test_collect_metadata_root_certificates_supports_object_and_mapping_shapes():
    root_a = b"root-a"
    root_b = b"root-b"

    metadata_entry_obj = SimpleNamespace(
        metadata_statement=SimpleNamespace(
            attestation_root_certificates=[root_a, base64.b64encode(root_b).decode("ascii")]
        )
    )

    roots_obj = attestation_trust._collect_metadata_root_certificates(metadata_entry_obj)
    assert roots_obj == [root_a, root_b]

    metadata_entry_map = {
        "attestationRootCertificates": [
            base64.b64encode(root_a).decode("ascii"),
            base64.b64encode(root_b).decode("ascii"),
        ]
    }
    roots_map = attestation_trust._collect_metadata_root_certificates(metadata_entry_map)
    assert roots_map == [root_a, root_b]


def test_is_trusted_ca_certificate_uses_fingerprint_and_subject_allowlists(monkeypatch):
    app = entry_app()

    cert_der = _self_signed_cert_der()
    certificate = x509.load_der_x509_certificate(cert_der)
    subject = certificate.subject.rfc4514_string()
    fingerprint = hashlib.sha256(cert_der).hexdigest().upper()

    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        {fingerprint},
    )
    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        set(),
    )
    with app.app_context():
        assert attestation_trust._is_trusted_ca_certificate(cert_der) is True

    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        {"NOT-A-MATCH"},
    )
    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        {subject},
    )
    with app.app_context():
        assert attestation_trust._is_trusted_ca_certificate(cert_der) is True

    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        {"CN=other"},
    )
    with app.app_context():
        assert attestation_trust._is_trusted_ca_certificate(cert_der) is False


def test_resolve_root_validity_handles_partial_success_and_failures():
    assert (
        attestation_trust._resolve_root_validity(
            {"trusted_ca": True, "chain": True, "fido_mds": None}
        )
        is True
    )
    assert (
        attestation_trust._resolve_root_validity(
            {"trusted_ca": True, "chain": False, "fido_mds": False}
        )
        is False
    )
    assert (
        attestation_trust._resolve_root_validity(
            {"trusted_ca": False, "chain": None, "fido_mds": None}
        )
        is None
    )


def test_serialize_extension_value_handles_known_unrecognized_oids_and_transport_bits():
    device_oid = ObjectIdentifier("1.3.6.1.4.1.41482.2")
    device_ext = SimpleNamespace(
        oid=device_oid,
        value=x509.UnrecognizedExtension(device_oid, b"\x04\x04demo"),
    )

    device_value = attestation_certificate_extensions._serialize_extension_value(device_ext)
    assert device_value["Device identifier"] == "demo"
    assert "Hex value" in device_value

    transports_oid = ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1")
    transports_ext = SimpleNamespace(
        oid=transports_oid,
        value=x509.UnrecognizedExtension(transports_oid, bytes.fromhex("03020430")),
    )
    transport_value = attestation_certificate_extensions._serialize_extension_value(transports_ext)
    assert transport_value["Transports"] == "USB NFC"


@pytest.mark.parametrize(
    ("der", "transports"),
    [
        # FIDO's named bits, bit 0 the first byte's most significant:
        # bluetoothRadio 0, bluetoothLowEnergyRadio 1, uSB 2, nFC 3, uSBInternal 4.
        ("03020780", ["BT CLASSIC"]),
        ("03020640", ["BLE"]),
        ("03020520", ["USB"]),
        ("03020410", ["NFC"]),
        ("03020308", ["USB INTERNAL"]),
        ("03020430", ["USB", "NFC"]),
        ("030204f0", ["BT CLASSIC", "BLE", "USB", "NFC"]),
        # A bit FIDO names nothing for is shown by its number.
        ("03020104", ["bit 5"]),
        ("030100", []),
    ],
)
def test_parse_fido_transport_bitfield_reads_fidos_named_bits(der, transports):
    assert attestation_certificate_extensions._parse_fido_transport_bitfield(bytes.fromhex(der)) == transports


@pytest.mark.parametrize("raw", [b"", b"\x03", b"\x04\x01\x00", bytes.fromhex("0302043000")])
def test_parse_fido_transport_bitfield_names_nothing_for_what_is_not_a_bit_string(raw):
    assert attestation_certificate_extensions._parse_fido_transport_bitfield(raw) is None


def test_coerce_attestation_certificate_bytes_handles_mapping_variants():
    cert_bytes = b"\x30\x82\x01\x00"
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(cert_bytes).decode("ascii")
        + "\n-----END CERTIFICATE-----"
    )

    assert attestation_certificates._coerce_attestation_certificate_bytes({"raw": cert_bytes.hex()}) == cert_bytes
    assert (
        attestation_certificates._coerce_attestation_certificate_bytes(
            {"derBase64": base64.b64encode(cert_bytes).decode("ascii")}
        )
        == cert_bytes
    )
    assert attestation_certificates._coerce_attestation_certificate_bytes({"pem": pem}) == cert_bytes
    assert attestation_certificates._coerce_attestation_certificate_bytes(ByteBuffer(cert_bytes)) == cert_bytes
