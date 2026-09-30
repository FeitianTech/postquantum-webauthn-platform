from __future__ import annotations

import base64

from server.app.decoder.decode import attestation_object as decode_attestation_object
from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import credential_json
from server.app.webauthn.attestation import certificates as attestation_certificates


def test_decode_public_key_credential_marks_authentication_without_attestation(monkeypatch):
    auth_bytes = b"\x00" * 37
    monkeypatch.setattr(
        decode_authenticator_data,
        "_describe_authenticator_data_bytes",
        lambda _value: {"parsed": True},
    )

    credential = {
        "id": "cred-id",
        "type": "public-key",
        "response": {
            "authenticatorData": base64.b64encode(auth_bytes).decode("ascii"),
        },
    }

    result = credential_json.decode_public_key_credential(credential)
    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"] == {"parsed": True}


def test_extract_attestation_certificate_handles_non_string_chain_entries_and_serializer_errors(monkeypatch):
    class _BytesEntry:
        def __bytes__(self):
            return b"\x01\x02"

    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda _cert: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert decode_attestation_object.extract_certificate({"x5c": [_BytesEntry()]}) is None

    class _BadBytesEntry:
        def __bytes__(self):
            raise TypeError("bad-bytes")

    assert decode_attestation_object.extract_certificate({"x5c": [_BadBytesEntry()]}) is None
