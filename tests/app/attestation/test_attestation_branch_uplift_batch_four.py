from __future__ import annotations

import pytest
from cryptography import x509
from fido2.webauthn import Aaguid

from tests.app.entry_app import entry_app


def test_hex_format_helpers_cover_empty_odd_and_invalid_inputs(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module.format_hex_bytes_lines(b"") == []
    assert attestation_module.format_hex_string_lines("abc", bytes_per_line=2) == ["0a:bc"]
    assert attestation_module.format_hex_string_lines("zz") == ["zz"]


def test_extract_certificate_aaguid_handles_missing_and_nonstandard_extension_shapes(monkeypatch, formatting, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module._extract_certificate_aaguid(b"") == b""

    class _MissingExtensionCert:
        class extensions:
            @staticmethod
            def get_extension_for_oid(_oid):
                raise x509.ExtensionNotFound("missing", x509.ObjectIdentifier("1.2.3"))

    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _der: _MissingExtensionCert(),
    )
    assert attestation_module._extract_certificate_aaguid(b"cert") == b""

    class _BytesValue:
        value = b"\x01" * 16

    class _BytesExtension:
        value = _BytesValue()

    class _BytesCert:
        class extensions:
            @staticmethod
            def get_extension_for_oid(_oid):
                return _BytesExtension()

    monkeypatch.setattr(
        formatting,
        "decode_asn1_octet_string",
        lambda _value: b"\x00" * 5,
    )
    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _der: _BytesCert(),
    )
    assert attestation_module._extract_certificate_aaguid(b"cert") == (b"\x01" * 16)

    class _NoUsableValue:
        value = object()

    class _NoUsableExtension:
        value = _NoUsableValue()

    class _NoUsableCert:
        class extensions:
            @staticmethod
            def get_extension_for_oid(_oid):
                return _NoUsableExtension()

    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _der: _NoUsableCert(),
    )
    assert attestation_module._extract_certificate_aaguid(b"cert") == b""


def test_coerce_certificate_bytes_non_bytes_path(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module._coerce_certificate_bytes(12345) is None


def test_collect_metadata_roots_handles_singleton_and_missing_candidates(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    metadata_entry = {
        "attestationRootCertificates": "AQID",
    }
    roots = attestation_module._collect_metadata_root_certificates(metadata_entry)
    assert roots == [b"\x01\x02\x03"]

    assert attestation_module._collect_metadata_root_certificates({"other": "value"}) == []


def test_trusted_ca_helpers_cover_list_configs_and_subject_parse_failure(monkeypatch, trust, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")
    app = entry_app()

    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        ["CN=Root A", "CN=Root B"],
    )
    monkeypatch.setitem(
        app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        ["aa", "bb"],
    )

    with app.app_context():
        assert attestation_module._trusted_ca_subjects() == {"CN=Root A", "CN=Root B"}
        assert attestation_module._trusted_ca_fingerprints() == {"AA", "BB"}

    monkeypatch.setattr(
        trust,
        "_certificate_fingerprint",
        lambda _cert_bytes: "NO_MATCH",
    )
    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _der: (_ for _ in ()).throw(ValueError("cannot parse subject")),
    )

    with app.app_context():
        assert attestation_module._is_trusted_ca_certificate(b"cert", allow_subject_parsing=True) is False


def test_find_metadata_entry_for_aaguid_handles_parse_and_lookup_failures(monkeypatch, attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    monkeypatch.setattr(
        Aaguid,
        "fromhex",
        lambda _hex: (_ for _ in ()).throw(ValueError("bad-aaguid")),
    )
    assert attestation_module._find_metadata_entry_for_aaguid(object(), b"\x00" * 16) is None

    monkeypatch.setattr(Aaguid, "fromhex", lambda _hex: object())

    class _Verifier:
        def find_entry_by_aaguid(self, _aaguid):
            raise RuntimeError("lookup failed")

    assert attestation_module._find_metadata_entry_for_aaguid(_Verifier(), b"\x00" * 16) is None
