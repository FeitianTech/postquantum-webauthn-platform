from __future__ import annotations

from server.app.decoder.decode import attestation_object as decode_attestation_object
from server.app.decoder.decode import certificates as decode_certificates


def test_decoder_residual_helpers_cover_remaining_parse_and_conversion_guards(monkeypatch, cbor_parser, ctap):
    # _extract_attestation_certificate and _convert_certificate_bytes/payload guards.
    assert decode_attestation_object.extract_certificate("not-a-map") is None
    assert decode_attestation_object.extract_certificate({"x5c": ["A"]}) is None

    assert decode_certificates.convert_certificate_bytes("A") == {}
    assert decode_certificates.convert_certificate_bytes(123) == {}
    assert decode_certificates.convert_certificate_payload("not-a-map") == {}
    assert decode_certificates.convert_certificate_payload({"derBase64": "A"})["parsedX5c"]["derBase64"] == "A"
