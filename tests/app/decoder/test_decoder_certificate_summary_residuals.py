from __future__ import annotations

import pytest


def test_decoder_certificate_summary_and_generic_format_residual_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    generic = decode_module._format_generic_summary(
        {"format": "hex", "decoded": None, "binary": {"hex": "aa"}}
    )
    assert any(line.startswith("Binary") for line in generic)

    assert decode_module._build_certificate_summary_lines("not-a-map") == []

    monkeypatch.setattr(
        decode_module,
        "_build_subject_public_key_info_lines",
        lambda _info: ["Subject Public Key Info:"],
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_certificate_extensions_lines",
        lambda _extensions: ["X509v3 extensions:"],
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_signature_lines",
        lambda _signature: ["Signature:"],
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_fingerprint_lines",
        lambda _fingerprints: ["Fingerprint:"],
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_subject_key_identifier_lines",
        lambda _decoded: ["aa:bb"],
        raising=False,
    )

    summary_lines = decode_module._build_certificate_summary_lines(
        {
            "version": {"display": "3 (0x2)"},
            "serialNumber": {"decimal": "123"},
            "signatureAlgorithm": "ECDSA",
            "issuer": "CN=Issuer",
            "validity": {"notBefore": "2020-01-01T00:00:00+00:00", "notAfter": "2021-01-01T00:00:00+00:00"},
            "subject": "CN=Subject",
        }
    )
    assert "Certificate Serial Number: 123" in summary_lines
    assert "Subject key identifier:" in summary_lines


def test_certificate_time_public_key_info_and_extension_header_fallbacks():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # timezone-aware conversion path
    assert decode_module._format_certificate_time("2020-01-01T00:00:00+02:00") == "2019-12-31T22:00:00"
    assert decode_module._format_certificate_time(123) is None

    assert decode_module._build_subject_public_key_info_lines("not-a-map") == []
    key_lines = decode_module._build_subject_public_key_info_lines(
        {
            "type": "ECC",
            "algorithm": {"namedCurve": "P-256"},
        }
    )
    assert "Type: ECC" in key_lines
    assert "Curve: P-256" in key_lines

    assert (
        decode_module._format_certificate_extension_header(
            {"includeOidInHeader": False, "friendlyName": "Friendly Label", "oid": None}
        )
        == "Friendly Label"
    )