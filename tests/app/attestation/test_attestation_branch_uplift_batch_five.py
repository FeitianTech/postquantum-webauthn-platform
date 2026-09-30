from __future__ import annotations

import hashlib
from types import SimpleNamespace

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)


class _ClientData:
    def __init__(self, challenge: bytes):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = "https://example.com"
        self.cross_origin = False
        self.hash = hashlib.sha256(b"client-data").digest()
        self.b64 = None

    def __bytes__(self):
        return b"client-data-json"


class _AttestationObject:
    def __init__(self, *, fmt: str, att_stmt, auth_data):
        self.fmt = fmt
        self.att_stmt = att_stmt
        self.auth_data = auth_data

    def __bytes__(self):
        return b"attestation-object"


class _AuthData:
    def __init__(self, *, rp_id_hash: bytes, flags, counter: int, credential_data):
        self.rp_id_hash = rp_id_hash
        self.flags = flags
        self.counter = counter
        self.credential_data = credential_data

    def __bytes__(self):
        return b"auth-data"


def _registration(attestation_object, client_data, extension_results):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results=extension_results,
    )


def test_serialize_extension_value_unrecognized_oid_fallback_paths(monkeypatch, formatting, attestation_module):
    firmware_oid = ObjectIdentifier("1.3.6.1.4.1.41482.13.1")
    security_key_oid = ObjectIdentifier("1.3.6.1.4.1.41482.1.1")
    aaguid_oid = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

    def _decode_stub(raw_value: bytes) -> bytes:
        if raw_value == b"firmware":
            return b""
        if raw_value == b"security":
            return b"\xff\xfe"
        return b"short"

    monkeypatch.setattr(formatting, "der_octet_string_content", _decode_stub)

    firmware_ext = SimpleNamespace(
        oid=firmware_oid,
        value=x509.UnrecognizedExtension(firmware_oid, b"firmware"),
    )
    security_ext = SimpleNamespace(
        oid=security_key_oid,
        value=x509.UnrecognizedExtension(security_key_oid, b"security"),
    )
    aaguid_ext = SimpleNamespace(
        oid=aaguid_oid,
        value=x509.UnrecognizedExtension(aaguid_oid, b"aaguid"),
    )

    assert "Hex value" in attestation_certificate_extensions._serialize_extension_value(firmware_ext)
    assert "Hex value" in attestation_certificate_extensions._serialize_extension_value(security_ext)
    assert "Hex value" in attestation_certificate_extensions._serialize_extension_value(aaguid_ext)
