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


def test_normalise_pqc_algorithm_identifier_handles_numeric_name_and_embedded_values():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._normalise_pqc_algorithm_identifier(-49) == -49
    assert attestation_module._normalise_pqc_algorithm_identifier("-48") == -48
    assert attestation_module._normalise_pqc_algorithm_identifier("ML-DSA-87") == -50
    assert attestation_module._normalise_pqc_algorithm_identifier("algorithm:-49") == -49
    assert attestation_module._normalise_pqc_algorithm_identifier("not-an-alg") is None


def test_collect_trust_path_entries_and_certificate_bytes_coercion_helpers():
    attestation_module = pytest.importorskip("server.app.attestation")

    trust_path = attestation_module._collect_trust_path_entries(
        [b"leaf", bytearray(b"intermediate"), "ignored", ByteBuffer(b"root")]
    )
    assert trust_path == [b"leaf", b"intermediate", b"root"]

    cert_bytes = b"\x30\x82\x01\x00"
    cert_b64 = base64.b64encode(cert_bytes).decode("ascii")

    assert attestation_module._coerce_certificate_bytes(cert_b64) == cert_bytes
    assert attestation_module._coerce_certificate_bytes("   ") is None


def test_collect_metadata_root_certificates_supports_object_and_mapping_shapes():
    attestation_module = pytest.importorskip("server.app.attestation")

    root_a = b"root-a"
    root_b = b"root-b"

    metadata_entry_obj = SimpleNamespace(
        metadata_statement=SimpleNamespace(
            attestation_root_certificates=[root_a, base64.b64encode(root_b).decode("ascii")]
        )
    )

    roots_obj = attestation_module._collect_metadata_root_certificates(metadata_entry_obj)
    assert roots_obj == [root_a, root_b]

    metadata_entry_map = {
        "attestationRootCertificates": [
            base64.b64encode(root_a).decode("ascii"),
            base64.b64encode(root_b).decode("ascii"),
        ]
    }
    roots_map = attestation_module._collect_metadata_root_certificates(metadata_entry_map)
    assert roots_map == [root_a, root_b]


def test_is_trusted_ca_certificate_uses_fingerprint_and_subject_allowlists(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    cert_der = _self_signed_cert_der()
    certificate = x509.load_der_x509_certificate(cert_der)
    subject = certificate.subject.rfc4514_string()
    fingerprint = hashlib.sha256(cert_der).hexdigest().upper()

    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        {fingerprint},
    )
    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        set(),
    )
    assert attestation_module._is_trusted_ca_certificate(cert_der) is True

    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        {"NOT-A-MATCH"},
    )
    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        {subject},
    )
    assert attestation_module._is_trusted_ca_certificate(cert_der) is True

    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        {"CN=other"},
    )
    assert attestation_module._is_trusted_ca_certificate(cert_der) is False


def test_resolve_root_validity_handles_partial_success_and_failures():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert (
        attestation_module._resolve_root_validity(
            {"trusted_ca": True, "chain": True, "fido_mds": None}
        )
        is True
    )
    assert (
        attestation_module._resolve_root_validity(
            {"trusted_ca": True, "chain": False, "fido_mds": False}
        )
        is False
    )
    assert (
        attestation_module._resolve_root_validity(
            {"trusted_ca": False, "chain": None, "fido_mds": None}
        )
        is None
    )


def test_serialize_extension_value_handles_known_unrecognized_oids_and_transport_bits():
    attestation_module = pytest.importorskip("server.app.attestation")

    device_oid = ObjectIdentifier("1.3.6.1.4.1.41482.2")
    device_ext = SimpleNamespace(
        oid=device_oid,
        value=x509.UnrecognizedExtension(device_oid, b"\x04\x04demo"),
    )

    device_value = attestation_module._serialize_extension_value(device_ext)
    assert device_value["Device identifier"] == "demo"
    assert "Hex value" in device_value

    transports_oid = ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1")
    transports_ext = SimpleNamespace(
        oid=transports_oid,
        value=x509.UnrecognizedExtension(transports_oid, b"\x03\x02\x00\x03"),
    )
    transport_value = attestation_module._serialize_extension_value(transports_ext)
    assert transport_value["Transports"] == "USB NFC"


def test_parse_fido_transport_bitfield_supports_plain_and_der_bitstring_encodings():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._parse_fido_transport_bitfield(b"\x03") == ["USB", "NFC"]
    assert attestation_module._parse_fido_transport_bitfield(b"\x03\x02\x00\x03") == [
        "USB",
        "NFC",
    ]
    assert attestation_module._parse_fido_transport_bitfield(b"") == []


def test_coerce_attestation_certificate_bytes_handles_mapping_variants():
    attestation_module = pytest.importorskip("server.app.attestation")

    cert_bytes = b"\x30\x82\x01\x00"
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(cert_bytes).decode("ascii")
        + "\n-----END CERTIFICATE-----"
    )

    assert attestation_module._coerce_attestation_certificate_bytes({"raw": cert_bytes.hex()}) == cert_bytes
    assert (
        attestation_module._coerce_attestation_certificate_bytes(
            {"derBase64": base64.b64encode(cert_bytes).decode("ascii")}
        )
        == cert_bytes
    )
    assert attestation_module._coerce_attestation_certificate_bytes({"pem": pem}) == cert_bytes
    assert attestation_module._coerce_attestation_certificate_bytes(ByteBuffer(cert_bytes)) == cert_bytes


def test_attempt_pqc_attestation_signature_validation_reports_missing_sig_and_algorithm_mismatch():
    attestation_module = pytest.importorskip("server.app.attestation")

    missing_sig_attestation = SimpleNamespace(att_stmt={"alg": -49}, auth_data=SimpleNamespace())
    missing_sig = attestation_module._attempt_pqc_attestation_signature_validation(
        missing_sig_attestation,
        b"\x11" * 32,
    )
    assert missing_sig["attempted"] is True
    assert missing_sig["success"] is False
    assert missing_sig["error"] == "pqc_attestation_missing_signature"

    auth_data = SimpleNamespace(
        credential_data=SimpleNamespace(
            public_key={1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        )
    )
    mismatch_attestation = SimpleNamespace(
        att_stmt={"alg": -49, "sig": b"signature"},
        auth_data=auth_data,
    )

    mismatch = attestation_module._attempt_pqc_attestation_signature_validation(
        mismatch_attestation,
        b"\x22" * 32,
    )

    assert mismatch["attempted"] is True
    assert mismatch["success"] is False
    assert mismatch["error"] == "pqc_attestation_algorithm_mismatch"


def test_check_pqc_certificate_constraints_returns_parse_error_for_invalid_der():
    attestation_module = pytest.importorskip("server.app.attestation")

    error = attestation_module._check_pqc_certificate_constraints(
        b"not-der",
        now=datetime.now(timezone.utc),
        is_leaf=True,
        remaining_subordinates=0,
    )

    assert isinstance(error, str)
    assert error.startswith("pqc_certificate_parse_error:")
