from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)
from server.app.webauthn.attestation import (
    certificate_names as attestation_certificate_names,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _CredentialData:
    def __init__(
        self,
        *,
        credential_id: object = b"credential-id",
        public_key: object | None = None,
        aaguid: object = bytes.fromhex("00112233445566778899aabbccddeeff"),
    ):
        self.credential_id = credential_id
        self.public_key = public_key or {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
        self.aaguid = aaguid


class _AuthData:
    def __init__(self, *, rp_id: str, flags: int, counter: int = 1, credential_data: _CredentialData | None = None):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = counter
        self.credential_data = credential_data or _CredentialData()

    def __bytes__(self):
        return b"auth-data"


class _ClientData:
    def __init__(self, *, challenge: bytes, origin: str, type_value: str = "webauthn.create", cross_origin: bool = False):
        self.type = type_value
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = cross_origin
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration(attestation_object, client_data):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results={},
    )


def test_serialize_extension_value_covers_authority_constraints_and_fallback_repr(attestation_module):
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo Issuer")])
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=b"\x01\x02",
        authority_cert_issuer=[x509.DirectoryName(issuer_name)],
        authority_cert_serial_number=17,
    )
    aki_value = attestation_certificate_extensions._serialize_extension_value(
        SimpleNamespace(oid=ObjectIdentifier("2.5.29.35"), value=aki)
    )
    assert "Authority Cert Serial Number" in aki_value
    assert aki_value["Authority Cert Issuer"]
    assert "Demo Issuer" in aki_value["Authority Cert Issuer"][0]

    constraints = attestation_certificate_extensions._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("2.5.29.19"),
            value=x509.BasicConstraints(ca=True, path_length=0),
        )
    )
    assert constraints["Path Length"] == 0

    firmware_value = attestation_certificate_extensions._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("1.3.6.1.4.1.41482.13.1"),
            value=x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.41482.13.1"),
                b"\x04\x03\x01\x02\x03",
            ),
        )
    )
    assert firmware_value == {"Firmware version": "1.2.3"}

    aaguid_fallback = attestation_certificate_extensions._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
            value=x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                b"\x04\x02\xAA\xBB",
            ),
        )
    )
    assert "Hex value" in aaguid_fallback

    class _BadStr:
        def __str__(self):
            raise RuntimeError("cannot stringify")

        def __repr__(self):
            return "<bad-str-value>"

    fallback_repr = attestation_certificate_extensions._serialize_extension_value(
        SimpleNamespace(oid=ObjectIdentifier("1.2.3"), value=_BadStr())
    )
    assert fallback_repr == "<bad-str-value>"


def test_format_x509_name_falls_back_to_string_when_rfc4514_fails(attestation_module):
    class _BrokenName:
        def rfc4514_string(self):
            raise ValueError("cannot format")

        def __str__(self):
            return "BrokenNameFallback"

    assert attestation_certificate_names.format_x509_name(_BrokenName()) == "BrokenNameFallback"
