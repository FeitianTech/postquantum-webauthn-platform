from __future__ import annotations

import base64

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

from server.app.decoder.decode import certificates as decode_certificates
from server.app.decoder.decode import ctap_auth_data as decode_ctap_auth_data


def test_parse_authenticator_data_bytes_reports_truncated_attested_data_instead_of_dropping_it():
    truncated_payload = b"\x00" * 32 + bytes([AuthenticatorData.FLAG.AT]) + (1).to_bytes(4, "big")
    details, trimmed, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(truncated_payload)
    assert details["attestedCredentialData"] == {
        "parseError": "Attested credential data truncated: it needs at least 18 bytes, 0 remain."
    }
    assert trimmed == truncated_payload
    assert trailing == b""

    mismatch_payload = (
        b"\x01" * 32
        + bytes([AuthenticatorData.FLAG.AT])
        + (2).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (4).to_bytes(2, "big")
        + b"AB"
    )
    mismatch = decode_ctap_auth_data._parse_authenticator_data_bytes(mismatch_payload)[0]["attestedCredentialData"]
    assert mismatch["lengthMismatch"] is True
    assert mismatch["parseError"] == "The credential ID declares 4 bytes; 2 remain."
    assert "credentialPublicKey" not in mismatch


def test_parse_authenticator_data_bytes_shows_a_cose_key_that_is_not_well_formed_as_hex_with_its_location():
    payload_with_bad_cose = (
        b"\x01" * 32
        + bytes([AuthenticatorData.FLAG.AT])
        + (2).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (2).to_bytes(2, "big")
        + b"AB"
        + b"\xa1"
    )

    details, trimmed, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(payload_with_bad_cose)

    attested = details["attestedCredentialData"]
    assert attested["credentialPublicKey"] == "a1"
    assert attested["parseError"] == (
        "credentialPublicKey is not well-formed CBOR at authData offset 58: "
        "map declares 1 entry; the data ends after 0"
    )
    assert trimmed == payload_with_bad_cose
    assert trailing == b""


def test_parse_authenticator_data_bytes_reads_extensions_and_reports_bytes_after_them():
    extension_payload = (
        b"\x03" * 32
        + bytes([AuthenticatorData.FLAG.ED])
        + (3).to_bytes(4, "big")
        + cbor.encode(7)
    )
    details, _, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(extension_payload)
    assert details["extensions"] == 7
    assert trailing == b""

    details, trimmed, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(extension_payload + b"\x99")
    assert details["extensions"] == 7
    assert trimmed == extension_payload
    assert trailing == b"\x99"


def test_attestation_entry_and_payload_helpers_cover_remaining_edges():
    assert decode_certificates.convert_attestation_entry("not-mapping") == {}

    cert_bytes = b"\x30\x82\x01\x00"
    cert_payload = {
        "raw": cert_bytes.hex(),
        "derBase64": base64.b64encode(cert_bytes).decode("ascii"),
    }
    converted_attestation = decode_certificates.convert_attestation_entry(
        {
            "details": {
                "cbor": {"fmt": "packed"},
                "attestationStatement": {"x5c": []},
                "attestationCertificates": [cert_payload],
            }
        }
    )
    assert converted_attestation["fmt"] == "packed"
    assert converted_attestation["attStmt"]["x5c"]
