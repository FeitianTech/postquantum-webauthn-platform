from __future__ import annotations

import hashlib

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

from server.app.decoder.decode import attestation_object as decode_attestation_object
from server.app.decoder.decode import certificates as decode_certificates
from server.app.decoder.decode import ctap_auth_data as decode_ctap_auth_data
from server.app.decoder.decode import response as decode_response


def test_decoder_residual_helpers_cover_remaining_parse_and_conversion_guards(monkeypatch, cbor_parser, ctap):
    # _extract_attestation_certificate and _convert_certificate_bytes/payload guards.
    assert decode_attestation_object.extract_certificate("not-a-map") is None
    assert decode_attestation_object.extract_certificate({"x5c": ["A"]}) is None

    assert decode_certificates.convert_certificate_bytes("A") == {}
    assert decode_certificates.convert_certificate_bytes(123) == {}
    assert decode_certificates.convert_certificate_payload("not-a-map") == {}
    assert decode_certificates.convert_certificate_payload({"derBase64": "A"})["parsedX5c"]["derBase64"] == "A"

    # _convert_client_data_entry edge paths.
    assert decode_response._convert_client_data_entry("not-a-map") == {}
    assert decode_response._convert_client_data_entry({"details": "not-a-map"}) == {}
    challenge_payload = decode_response._convert_client_data_entry(
        {"details": {"type": "webauthn.create", "challenge": {"nested": "value"}}}
    )
    assert challenge_payload["challenge"] == {"nested": "value"}

    # _parse_authenticator_data_bytes branch for non-mapping COSE value and extension decode exceptions.
    auth_with_cose_int = (
        b"\x01" * 32
        + bytes([AuthenticatorData.FLAG.AT])
        + (1).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (0).to_bytes(2, "big")
        + cbor.encode(5)
    )
    details, _, _ = decode_ctap_auth_data._parse_authenticator_data_bytes(auth_with_cose_int)
    assert details["attestedCredentialData"]["credentialPublicKey"] == 5

    # Extensions that are not well-formed CBOR are shown as their bytes with
    # where they break, not dropped.
    broken_extensions = cbor.encode({"ext": True})[:-1]
    extension_payload = (
        hashlib.sha256(b"example.com").digest()
        + bytes([AuthenticatorData.FLAG.ED])
        + (1).to_bytes(4, "big")
        + broken_extensions
    )
    details, _, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(extension_payload)
    assert details["extensions"] == broken_extensions.hex()
    assert details["parseError"] == (
        'extensions is not well-formed CBOR at authData offset 38: map key "ext" has no value'
    )
    assert trailing == b""
