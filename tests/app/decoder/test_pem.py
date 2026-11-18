"""Tests of pem behavior."""

import base64
import time

import pytest

from server.app.decoder.decode import pem as decode_pem
from tests.app.python_fido2_vectors import GSR2_DER as _GSR2_DER


def _pem_block(der_bytes: bytes) -> str:
    body = base64.b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def test_decode_pem_certificates_ignores_invalid_blocks_and_keeps_valid_certificates():
    invalid_block = "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----"
    pem_bundle = "\n".join([_pem_block(_GSR2_DER), invalid_block, _pem_block(_GSR2_DER)])

    result = decode_pem.decode_pem_certificates(pem_bundle)

    assert result["format"] == "X.509 certificate (PEM)"
    assert result["inputEncoding"] == "pem"
    decoded = result["decoded"]
    assert isinstance(decoded, dict)
    assert "rawPem" in decoded
    assert decoded["rawPem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "certificates" in decoded
    assert len(decoded["certificates"]) == 2
    assert all(isinstance(cert.get("fingerprints"), dict) for cert in decoded["certificates"])


def test_decode_pem_certificates_rejects_payload_without_any_valid_pem_certificate():
    pem_text = "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----"

    with pytest.raises(ValueError, match="No PEM certificate data found"):
        decode_pem.decode_pem_certificates(pem_text)


def test_try_decode_certificate_bytes_returns_none_for_malformed_der_payload():
    malformed_der = _GSR2_DER[:24]

    assert decode_pem.try_decode_der_certificate(malformed_der, "base64url") is None


def test_decode_pem_certificates_reads_a_body_with_blank_lines_and_spaces_around_it():
    body = base64.b64encode(_GSR2_DER).decode("ascii")
    pem_text = f"-----BEGIN CERTIFICATE-----\n\n   {body}  \n\n-----END CERTIFICATE-----"

    result = decode_pem.decode_pem_certificates(pem_text)

    assert isinstance(result["decoded"].get("fingerprints"), dict)


def test_decode_pem_certificates_refuses_a_mebibyte_of_unclosed_begin_lines_quickly():
    # A quadratic scan takes minutes here; the bound leaves room for a slow, loaded machine.
    begin = "-----BEGIN CERTIFICATE-----\n"
    pem_text = begin * (1024 * 1024 // len(begin))

    start = time.perf_counter()
    with pytest.raises(ValueError, match="No PEM certificate data found"):
        decode_pem.decode_pem_certificates(pem_text)
    assert time.perf_counter() - start < 2
