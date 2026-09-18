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

PLAIN_TEXT = "Hello, this is plain text!"


@pytest.fixture()
def pipeline_runtime():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.decoder.decode.pipeline_runtime")


@pytest.fixture()
def shared_binary_helpers():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.routes.binary_helpers")


@pytest.fixture()
def advanced_binary_helpers():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.routes.advanced_parts.binary_helpers_impl")


@pytest.fixture()
def simple_binary_helpers():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.routes.simple_parts.binary_helpers_impl")


def test_decoder_rejects_plain_english_text(pipeline_runtime):
    """Prose is not base64url, and must not be reported as decoded CBOR."""

    with pytest.raises(ValueError):
        pipeline_runtime._decode_binary_input(PLAIN_TEXT)

    decode = pytest.importorskip("server.app.decoder.decode")
    with pytest.raises(ValueError):
        decode.decode_payload_text(PLAIN_TEXT)


def test_decoder_rejects_odd_length_hex_instead_of_left_padding_it(pipeline_runtime):
    """``abc`` is not ``0abc``; guessing a leading nibble invents data."""

    with pytest.raises(ValueError):
        pipeline_runtime._decode_binary_input("abc")

    assert pipeline_runtime._decode_binary_input("0abc") == (b"\x0a\xbc", "hex")


def test_decoder_reports_encoding_ambiguity_rather_than_guessing(pipeline_runtime):
    """A dash-free payload is valid under both base64 alphabets; say so."""

    ambiguous = pipeline_runtime._sniff_binary_input("QUJD")
    assert ambiguous.data == b"ABC"
    assert ambiguous.ambiguous is True

    urlsafe = pipeline_runtime._sniff_binary_input(
        base64.urlsafe_b64encode(b"\xfb\xef\xbe").decode("ascii").rstrip("=")
    )
    assert urlsafe.encoding == "base64url"
    assert urlsafe.ambiguous is False


def test_advanced_client_binary_rejects_plain_text(advanced_binary_helpers):
    with pytest.raises(ValueError):
        advanced_binary_helpers._decode_client_binary_impl(PLAIN_TEXT)


def test_simple_binary_value_rejects_plain_text(simple_binary_helpers):
    with pytest.raises(ValueError):
        simple_binary_helpers._decode_binary_value_impl(PLAIN_TEXT)


def test_base64url_helpers_do_not_return_garbage_for_plain_text(shared_binary_helpers):
    """The credential-ID intake path must return nothing, not junk bytes."""

    assert shared_binary_helpers.decode_base64url_bytes(PLAIN_TEXT) == b""
    assert shared_binary_helpers.extract_assertion_credential_id({"rawId": PLAIN_TEXT}) is None

    for module_name in ("server.app.routes.advanced", "server.app.routes.simple"):
        route_module = pytest.importorskip(module_name)
        assert route_module._decode_base64url_bytes(PLAIN_TEXT) == b""
        assert route_module._extract_assertion_credential_id({"rawId": PLAIN_TEXT}) is None


def test_credential_intake_reads_both_base64_alphabets_exactly(
    advanced_binary_helpers, simple_binary_helpers
):
    raw = b"\xfb\xef\xbe\xff\xee\xdd"
    standard = base64.b64encode(raw).decode("ascii").rstrip("=")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard or "/" in standard
    assert "-" in urlsafe or "_" in urlsafe

    assert advanced_binary_helpers._decode_client_binary_impl(standard) == raw
    assert advanced_binary_helpers._decode_client_binary_impl(urlsafe) == raw
    assert simple_binary_helpers._decode_binary_value_impl(standard) == raw
    assert simple_binary_helpers._decode_binary_value_impl(urlsafe) == raw


def test_mds_certificate_route_decodes_base64url_without_truncation(monkeypatch):
    """A base64url certificate must decode whole, or be refused -- not truncated."""

    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    certificate = bytes(range(24, 63))
    monkeypatch.setattr(
        general_module,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
        raising=False,
    )

    urlsafe = base64.urlsafe_b64encode(certificate).decode("ascii").rstrip("=")
    assert "-" in urlsafe or "_" in urlsafe

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": urlsafe}
        )

    assert response.status_code == 200
    assert response.get_json() == {
        "details": {"length": 39, "hex": certificate.hex()}
    }
    assert len(certificate) == 39


def test_mds_certificate_route_refuses_plain_text_with_400(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        general_module,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": PLAIN_TEXT}
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid certificate encoding."}
