"""Regression tests for input that used to decode to the *wrong* bytes.

Each test here fails against the tree before the encoding unification. They
cover the four ways an open-coded decoder used to accept malformed input:

* ``base64.b64decode``/``urlsafe_b64decode`` default to ``validate=False`` and
  silently discard characters outside the alphabet, so prose "decodes";
* an odd number of hex digits was silently left-padded with ``0``;
* base64url reaching a standard-base64 decoder lost its ``-``/``_``;
* the recovered encoding was labelled by scanning for ``-``/``_`` rather than
  by which decoder matched.
"""

from __future__ import annotations

import base64

import pytest

from server.app.decoder.decode import binary_text
from server.app.decoder.decode import text as decode_text
from server.app.webauthn import client_binary
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app

PLAIN_TEXT = "Hello, this is plain text!"


def test_decoder_rejects_plain_english_text():
    """Prose is not base64url, and must not be reported as decoded CBOR."""

    with pytest.raises(ValueError):
        binary_text.decode_binary_input(PLAIN_TEXT)

    with pytest.raises(ValueError):
        decode_text.decode_payload_text(PLAIN_TEXT)


def test_decoder_never_left_pads_odd_length_hex():
    """``abc`` is not ``0abc``; guessing a leading nibble invents data.

    It is base64 (69 b7), and read as that; odd-length digits that are not
    base64 either are refused.
    """

    assert binary_text.decode_binary_input("abc") == (b"\x69\xb7", "base64 or base64url")
    with pytest.raises(ValueError):
        binary_text.decode_binary_input("abcde")

    assert binary_text.decode_binary_input("0abc") == (b"\x0a\xbc", "hex")


def test_decoder_reports_encoding_ambiguity_rather_than_guessing():
    """A dash-free payload is valid under both base64 alphabets; say so."""

    ambiguous = binary_text.sniff_binary_input("QUJD")
    assert ambiguous.data == b"ABC"
    assert ambiguous.ambiguous is True

    urlsafe = binary_text.sniff_binary_input(
        base64.urlsafe_b64encode(b"\xfb\xef\xbe").decode("ascii").rstrip("=")
    )
    assert urlsafe.encoding == "base64url"
    assert urlsafe.ambiguous is False


def test_advanced_client_binary_rejects_plain_text():
    with pytest.raises(ValueError):
        client_binary.read(PLAIN_TEXT, wrappers=True)


def test_simple_binary_value_rejects_plain_text():
    with pytest.raises(ValueError):
        client_binary.read(PLAIN_TEXT, iterables=True)


def test_base64url_helpers_do_not_return_garbage_for_plain_text():
    """The credential-ID intake path must return nothing, not junk bytes."""

    assert client_binary.decode_base64url_bytes(PLAIN_TEXT) == b""
    assert client_binary.extract_assertion_credential_id({"rawId": PLAIN_TEXT}) is None


def test_credential_intake_reads_both_base64_alphabets_exactly():
    raw = b"\xfb\xef\xbe\xff\xee\xdd"
    standard = base64.b64encode(raw).decode("ascii").rstrip("=")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard or "/" in standard
    assert "-" in urlsafe or "_" in urlsafe

    assert client_binary.read(standard, wrappers=True) == raw
    assert client_binary.read(urlsafe, wrappers=True) == raw
    assert client_binary.read(standard, iterables=True) == raw
    assert client_binary.read(urlsafe, iterables=True) == raw


def test_mds_certificate_route_decodes_base64url_without_truncation(monkeypatch):
    """A base64url certificate must decode whole, or be refused -- not truncated."""

    certificate = bytes(range(24, 63))
    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
    )

    urlsafe = base64.urlsafe_b64encode(certificate).decode("ascii").rstrip("=")
    assert "-" in urlsafe or "_" in urlsafe

    with entry_app().test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": urlsafe}
        )

    assert response.status_code == 200
    assert response.get_json() == {
        "details": {"length": 39, "hex": certificate.hex()}
    }
    assert len(certificate) == 39


def test_mds_certificate_route_refuses_plain_text_with_400(monkeypatch):
    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": PLAIN_TEXT}
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid certificate encoding."}
