from __future__ import annotations

import cbor2

from server.app.decoder.decode import certificates as decode_certificates
from server.app.decoder.decode import ctap_classify as decode_ctap_classify
from server.app.webauthn.attestation import certificates as attestation_certificates


def test_remaining_mapping_and_auth_data_format_helpers():
    mapping = {1: "packed", 2: b"\xaa\xbb"}
    assert decode_ctap_classify._extract_mapping_string(mapping, (1, "fmt")) == "packed"
    assert decode_ctap_classify._extract_mapping_bytes(mapping, (2, "authData")) == b"\xaa\xbb"


def test_remaining_certificate_conversion_helpers(monkeypatch):
    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda cert_bytes: {
            "derBase64": cbor2.dumps(cert_bytes).hex(),
            "pem": "PEM",
            "subject": "CN=Demo",
        },
    )

    chain = decode_certificates.convert_certificate_chain([b"\x01\x02", "AQI=", {"derBase64": "AQI="}])
    assert len(chain) == 3

    converted_bytes = decode_certificates.convert_certificate_bytes("AQI=")
    assert "parsedX5c" in converted_bytes

    converted_payload = decode_certificates.convert_certificate_payload({"derBase64": "AQI=", "pem": "PEM"})
    assert converted_payload["raw"] == "0102"
    assert converted_payload["pem"] == "PEM"
