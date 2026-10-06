"""``decoder.decode.certificates``: an attestation's certificates as the decoder's answer shows them."""

from __future__ import annotations

import base64

import pytest

from server.app.decoder.decode import certificates as decode_certificates
from tests.app.characterization import material
from tests.app.python_fido2_vectors import GSR2_DER as _GSR2_DER

CERTIFICATE = material.certificate(material.ec_key("decoder-certificates").public_key(), common_name="Decoded", serial=0xDE)


def test_certificate_bytes_are_shown_as_hex_pem_and_parsed_fields():
    converted = decode_certificates.convert_certificate_bytes(base64.b64encode(CERTIFICATE).decode("ascii"))

    assert converted["raw"] == CERTIFICATE.hex()
    assert converted["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert converted["parsedX5c"]["subject"] == "CN=Decoded,OU=Authenticator Attestation,O=Characterization Test,C=SE"
    assert "summary" not in converted["parsedX5c"]


@pytest.mark.parametrize("value", [b"", "%%", "A", 123])
def test_what_is_no_certificate_shows_nothing(value):
    assert decode_certificates.convert_certificate_bytes(value) == {}


def test_a_certificate_the_views_already_read_is_shown_from_its_fields():
    assert decode_certificates.convert_certificate_payload({"derBase64": "AQI=", "pem": "PEM"}) == {
        "raw": "0102",
        "pem": "PEM",
        "parsedX5c": {"derBase64": "AQI=", "pem": "PEM"},
    }
    assert decode_certificates.convert_certificate_payload({"derBase64": "A", "pem": "  "}) == {
        "parsedX5c": {"derBase64": "A", "pem": "  "}
    }
    assert decode_certificates.convert_certificate_payload("not-a-map") == {}


def test_a_chain_shows_each_certificate_it_holds_and_skips_what_is_none():
    chain = decode_certificates.convert_certificate_chain([CERTIFICATE, {"derBase64": "AQI="}, "%%"])

    assert [entry["raw"] for entry in chain] == [CERTIFICATE.hex(), "0102"]
    assert decode_certificates.convert_certificate_chain("not-a-list") == []


def test_an_attestation_statement_is_read_from_its_details_or_else_its_cbor():
    assert decode_certificates.convert_attestation_statement({"cbor": {"attStmt": {"sig": b"\xaa"}}}) == {"sig": "aa"}
    assert decode_certificates.convert_attestation_statement({"cbor": {"attStmt": "not-a-map"}}) == {}
    assert decode_certificates.convert_attestation_statement("not-a-map") == {}


def test_an_attestation_without_x5c_certificates_shows_the_one_its_details_read():
    converted = decode_certificates.convert_attestation_entry(
        {
            "details": {
                "cbor": {"fmt": "packed"},
                "attestationStatement": {"x5c": []},
                "attestationCertificates": [{"derBase64": "AQI="}],
            }
        }
    )

    assert converted == {"fmt": "packed", "attStmt": {"x5c": [{"raw": "0102", "parsedX5c": {"derBase64": "AQI="}}]}}
    assert decode_certificates.convert_attestation_entry("not-a-mapping") == {}


def test_convert_attestation_entry_injects_certificate_when_x5c_is_empty():
    der_b64 = base64.b64encode(_GSR2_DER).decode("ascii")
    entry = {
        "raw": "raw-attestation",
        "details": {
            "attestationFormat": "packed",
            "attestationStatement": {
                "alg": -7,
                "sig": b"\x01\x02",
                "x5c": [],
            },
            "attestationCertificate": {
                "derBase64": der_b64,
                "pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----",
                "subject": "CN=Demo",
            },
        },
    }

    converted = decode_certificates.convert_attestation_entry(entry)

    assert converted["fmt"] == "packed"
    assert converted["attStmt"]["sig"] == "0102"
    assert len(converted["attStmt"]["x5c"]) == 1
    assert "parsedX5c" in converted["attStmt"]["x5c"][0]
