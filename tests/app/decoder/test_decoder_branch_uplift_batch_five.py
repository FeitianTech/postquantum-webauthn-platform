from __future__ import annotations

import base64

from server.app.decoder.decode import certificates as decode_certificates


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
