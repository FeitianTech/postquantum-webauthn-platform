from __future__ import annotations

import cbor2
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import certificates as decode_certificates
from server.app.decoder.decode import ctap_auth_data as decode_ctap_auth_data
from server.app.decoder.decode import ctap_classify as decode_ctap_classify
from server.app.webauthn.attestation import certificates as attestation_certificates


def _auth_data_bytes() -> bytes:
    credential_id = b"decoder-remaining"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        b"\x11" * 32,
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        3,
        credential_data,
    )
    return bytes(auth_data)


def test_remaining_mapping_and_auth_data_format_helpers():
    mapping = {1: "packed", 2: b"\xaa\xbb"}
    assert decode_ctap_classify._extract_mapping_string(mapping, (1, "fmt")) == "packed"
    assert decode_ctap_classify._extract_mapping_bytes(mapping, (2, "authData")) == b"\xaa\xbb"

    auth_details, trailing = decode_ctap_auth_data._format_auth_data_for_expanded_json(_auth_data_bytes())
    assert auth_details["signCount"] == 3
    assert isinstance(trailing, bytes)


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
