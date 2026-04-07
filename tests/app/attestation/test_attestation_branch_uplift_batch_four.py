from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509


def test_hex_format_helpers_cover_empty_odd_and_invalid_inputs():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module.format_hex_bytes_lines(b"") == []
    assert attestation_module.format_hex_string_lines("abc", bytes_per_line=2) == ["0a:bc"]
    assert attestation_module.format_hex_string_lines("zz") == ["zz"]


def test_extract_certificate_aaguid_handles_missing_and_nonstandard_extension_shapes(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._extract_certificate_aaguid(b"") == b""

    class _MissingExtensionCert:
        class extensions:
            @staticmethod
            def get_extension_for_oid(_oid):
                raise x509.ExtensionNotFound("missing", x509.ObjectIdentifier("1.2.3"))

    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: _MissingExtensionCert(),
        raising=False,
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
        attestation_module,
        "decode_asn1_octet_string",
        lambda _value: b"\x00" * 5,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: _BytesCert(),
        raising=False,
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
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: _NoUsableCert(),
        raising=False,
    )
    assert attestation_module._extract_certificate_aaguid(b"cert") == b""


def test_coerce_certificate_bytes_and_leaf_extraction_non_mapping_paths():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._coerce_certificate_bytes(12345) is None

    attestation_object = SimpleNamespace(att_stmt="not-a-mapping")
    assert attestation_module._extract_attestation_leaf_certificate(attestation_object) is None


def test_collect_metadata_roots_handles_singleton_and_missing_candidates():
    attestation_module = pytest.importorskip("server.app.attestation")

    metadata_entry = {
        "attestationRootCertificates": "AQID",
    }
    roots = attestation_module._collect_metadata_root_certificates(metadata_entry)
    assert roots == [b"\x01\x02\x03"]

    assert attestation_module._collect_metadata_root_certificates({"other": "value"}) == []


def test_trusted_ca_helpers_cover_list_configs_and_subject_parse_failure(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_SUBJECTS",
        ["CN=Root A", "CN=Root B"],
    )
    monkeypatch.setitem(
        attestation_module.app.config,
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
        ["aa", "bb"],
    )

    assert attestation_module._trusted_ca_subjects() == {"CN=Root A", "CN=Root B"}
    assert attestation_module._trusted_ca_fingerprints() == {"AA", "BB"}

    monkeypatch.setattr(
        attestation_module,
        "_certificate_fingerprint",
        lambda _cert_bytes: "NO_MATCH",
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: (_ for _ in ()).throw(ValueError("cannot parse subject")),
        raising=False,
    )

    assert attestation_module._is_trusted_ca_certificate(b"cert", allow_subject_parsing=True) is False


def test_find_metadata_entry_for_aaguid_handles_parse_and_lookup_failures(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(
        attestation_module.Aaguid,
        "fromhex",
        lambda _hex: (_ for _ in ()).throw(ValueError("bad-aaguid")),
        raising=False,
    )
    assert attestation_module._find_metadata_entry_for_aaguid(object(), b"\x00" * 16) is None

    monkeypatch.setattr(attestation_module.Aaguid, "fromhex", lambda _hex: object(), raising=False)

    class _Verifier:
        def find_entry_by_aaguid(self, _aaguid):
            raise RuntimeError("lookup failed")

    assert attestation_module._find_metadata_entry_for_aaguid(_Verifier(), b"\x00" * 16) is None


def test_check_pqc_certificate_constraints_reports_validity_basic_constraints_and_usage_errors(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    now = datetime.now(timezone.utc)

    class _Extensions:
        def __init__(self, mapping):
            self._mapping = mapping

        def get_extension_for_class(self, cls):
            value = self._mapping.get(cls)
            if value is None:
                raise x509.ExtensionNotFound("missing", x509.ObjectIdentifier("1.2.3"))
            return SimpleNamespace(value=value)

    class _Cert:
        def __init__(self, extensions):
            self.extensions = _Extensions(extensions)
            self.subject = SimpleNamespace(rfc4514_string=lambda: "CN=Test")

    # Out-of-validity branch.
    monkeypatch.setattr(
        attestation_module,
        "_certificate_datetime",
        lambda _cert, attr: now + timedelta(days=1) if attr == "not_valid_before" else now + timedelta(days=2),
        raising=False,
    )
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: _Cert({}), raising=False)
    assert "pqc_certificate_out_of_validity" in attestation_module._check_pqc_certificate_constraints(
        b"cert",
        now=now,
        is_leaf=True,
        remaining_subordinates=0,
    )

    # CA required branch.
    monkeypatch.setattr(
        attestation_module,
        "_certificate_datetime",
        lambda _cert, _attr: now,
        raising=False,
    )
    not_ca = x509.BasicConstraints(ca=False, path_length=None)
    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: _Cert({x509.BasicConstraints: not_ca}),
        raising=False,
    )
    assert "pqc_basic_constraints_not_ca" in attestation_module._check_pqc_certificate_constraints(
        b"cert",
        now=now,
        is_leaf=False,
        remaining_subordinates=1,
    )

    # Path length branch.
    with_path_len = _Cert({x509.BasicConstraints: x509.BasicConstraints(ca=True, path_length=0)})
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: with_path_len, raising=False)
    assert "pqc_basic_constraints_path_length" in attestation_module._check_pqc_certificate_constraints(
        b"cert",
        now=now,
        is_leaf=False,
        remaining_subordinates=1,
    )

    # Key usage leaf invalid and CA invalid branches.
    leaf_usage_invalid = _Cert(
        {
            x509.BasicConstraints: x509.BasicConstraints(ca=False, path_length=None),
            x509.KeyUsage: x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        }
    )
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: leaf_usage_invalid, raising=False)
    assert "pqc_key_usage_leaf_invalid" in attestation_module._check_pqc_certificate_constraints(
        b"cert",
        now=now,
        is_leaf=True,
        remaining_subordinates=0,
    )

    ca_usage_invalid = _Cert(
        {
            x509.BasicConstraints: x509.BasicConstraints(ca=True, path_length=3),
            x509.KeyUsage: x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        }
    )
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: ca_usage_invalid, raising=False)
    assert "pqc_key_usage_ca_invalid" in attestation_module._check_pqc_certificate_constraints(
        b"cert",
        now=now,
        is_leaf=False,
        remaining_subordinates=0,
    )


def test_evaluate_mldsa_attestation_root_covers_untrusted_root_and_fido_status_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    metadata_entry = SimpleNamespace(metadata_statement=SimpleNamespace())
    monkeypatch.setattr(attestation_module, "_find_metadata_entry_for_aaguid", lambda *_args, **_kwargs: metadata_entry, raising=False)
    monkeypatch.setattr(attestation_module, "_collect_metadata_root_certificates", lambda _entry: [b"root"], raising=False)
    monkeypatch.setattr(attestation_module, "_is_trusted_ca_certificate", lambda *_args, **_kwargs: False, raising=False)

    untrusted = attestation_module._evaluate_mldsa_attestation_root(
        SimpleNamespace(att_stmt={"x5c": [b"leaf"]}),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        verifier=object(),
        now=datetime.now(timezone.utc),
    )
    assert "attestation_root_not_trusted" in untrusted["errors"]

    monkeypatch.setattr(attestation_module, "_is_trusted_ca_certificate", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(attestation_module, "metadata_entry_trust_anchor_status", lambda _entry: False, raising=False)
    monkeypatch.setattr(attestation_module, "_collect_trust_path_entries", lambda _x5c: [], raising=False)

    fido_false = attestation_module._evaluate_mldsa_attestation_root(
        SimpleNamespace(att_stmt={"x5c": [b"leaf"]}),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        verifier=object(),
        now=datetime.now(timezone.utc),
    )
    assert fido_false["checks"]["fido_mds"] is False
    assert "pqc_metadata_not_fido_trusted" in fido_false["errors"]


def test_attempt_pqc_signature_validation_skips_non_mapping_statements():
    attestation_module = pytest.importorskip("server.app.attestation")

    outcome = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt=["not-a-mapping"]),
        b"client-hash",
    )
    assert outcome["attempted"] is False
    assert outcome["success"] is False
