from __future__ import annotations

import hashlib
from types import MappingProxyType, SimpleNamespace

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from fido2.webauthn import RegistrationResponse

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)
from server.app.webauthn.attestation import certificates as attestation_certificates


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


def test_extract_attestation_details_handles_non_dict_and_certificate_edge_cases(monkeypatch, certificates, attestation_module):
    defaults = attestation_certificates.extract_attestation_details(["not-a-dict"])
    assert defaults[0] == "none"
    assert defaults[1] == {}

    attestation_object = _AttestationObject(
        fmt="packed",
        att_stmt={"x5c": ["bad", "good"]},
        auth_data=SimpleNamespace(),
    )
    registration = _registration(
        attestation_object,
        _ClientData(b"challenge"),
        MappingProxyType({"ext": True}),
    )

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: registration,
    )
    monkeypatch.setattr(
        certificates,
        "_coerce_attestation_certificate_bytes",
        lambda entry: None if entry == "bad" else b"cert-bytes",
    )
    monkeypatch.setattr(
        certificates,
        "serialize_attestation_certificate",
        lambda _cert: None,
    )

    extracted = attestation_certificates.extract_attestation_details({"ok": True})
    assert extracted[0] == "packed"
    assert extracted[5]["error"] == "Unable to decode attestation certificate bytes."
    assert extracted[6][1]["error"] == "Unable to parse attestation certificate."
    assert extracted[4] == {"ext": True}


def test_extract_attestation_details_keeps_non_mapping_extension_outputs(monkeypatch, attestation_module):
    attestation_object = _AttestationObject(fmt="none", att_stmt={}, auth_data=SimpleNamespace())
    registration = _registration(attestation_object, _ClientData(b"challenge"), ["raw-extension"])

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: registration,
    )

    extracted = attestation_certificates.extract_attestation_details({"ok": True})
    assert extracted[4] == ["raw-extension"]


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


def test_coerce_attestation_certificate_bytes_and_aaguid_field_cleanup_edges(attestation_module):
    assert attestation_certificates._coerce_attestation_certificate_bytes({"raw": "zz"}) is None
    assert attestation_certificates._coerce_attestation_certificate_bytes({"derBase64": "A"}) is None
    # A PEM body of "@@@" decodes to nothing at all now, rather than to b""
    # via a decoder that quietly discarded every character in it.
    assert attestation_certificates._coerce_attestation_certificate_bytes(
        {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}
    ) is None
