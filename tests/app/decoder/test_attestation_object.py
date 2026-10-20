"""``decoder.decode.attestation_object``: an attestation object's certificate, as the decoder reads it."""
from __future__ import annotations

import datetime
import tracemalloc

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from server.app.decoder.decode import attestation_object as decode_attestation_object


def test_the_first_x5c_entry_is_serialised_even_when_it_is_not_a_certificate():
    certificate = decode_attestation_object.extract_certificate({"x5c": ["AQI="]})

    assert certificate["error"].startswith("Unable to parse attestation certificate: ")
    assert certificate["raw"] == "0102"


@pytest.mark.parametrize(
    "statement",
    [
        "not-a-map",
        {},
        {"x5c": []},
        {"x5c": ["A"]},
        {"x5c": ["%%"]},
        {"x5c": [{"not": "bytes"}]},
        {"x5c": [{1: 2}]},
        {"x5c": [[48, 130]]},
        {"x5c": [True]},
        {"x5c": [7]},
    ],
)
def test_a_statement_without_a_readable_first_certificate_has_none(statement):
    assert decode_attestation_object.extract_certificate(statement) is None


def test_an_integer_first_x5c_entry_allocates_nothing_for_its_value():
    attestation = cbor2.dumps(
        {"fmt": "packed", "authData": bytes(32) + b"\x01" + bytes(4), "attStmt": {"alg": -7, "sig": b"s", "x5c": [10**6]}}
    )

    tracemalloc.start()
    try:
        details, _node, _end = decode_attestation_object.read(attestation)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The statement is shown as sent; no certificate is read from a number.
    assert details["attestationStatement"]["x5c"] == [10**6]
    assert "attestationCertificate" not in details
    assert peak < 100_000


def test_a_certificate_whose_extensions_cannot_be_read_is_shown_as_unparsed():
    # It loads, but reading its extensions fails: basic constraints holding no valid DER.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unreadable extension")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.UnrecognizedExtension(ExtensionOID.BASIC_CONSTRAINTS, b"\x00\x01"), critical=False)
        .sign(key, hashes.SHA256())
    )

    der = certificate.public_bytes(serialization.Encoding.DER)

    shown = decode_attestation_object.extract_certificate({"x5c": [der]})

    # As one that does not load is: what failed, and the bytes as sent.
    assert shown["error"].startswith("Unable to parse attestation certificate: ")
    assert shown["raw"] == der.hex()
