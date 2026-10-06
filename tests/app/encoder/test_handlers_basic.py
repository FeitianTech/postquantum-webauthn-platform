"""``decoder.encode.handlers_basic``: the encoder's formats, named in the Codec's words."""

from __future__ import annotations

import pytest

from server.app.decoder.encode import handlers_basic as encode_handlers_basic
from server.app.decoder.encode import text as encode_text


@pytest.mark.parametrize(("fmt", "error"), [("   ", "Encoder format must be provided"), ("XML", "Unsupported encoder format: XML")])
def test_a_format_must_be_one_the_codec_names(fmt, error):
    with pytest.raises(ValueError, match=error):
        encode_text.encode_payload_text('{"ok": true}', fmt)


@pytest.mark.parametrize(
    ("fmt", "written_as"),
    [
        ("  JSON (binary)  ", "JSON (encoded)"),
        ("CBOR (CANONICAL)", "CBOR (canonical) (encoded)"),
        ("cbor", "CBOR (canonical) (encoded)"),
        ("EDN (exact bytes)", "EDN (encoded)"),
    ],
)
def test_a_format_is_named_in_any_case_with_or_without_its_qualifier(fmt, written_as):
    assert encode_text.encode_payload_text('{"ok": true}', fmt)["type"] == written_as


def test_the_ctap_format_is_named_in_any_case():
    for fmt in ("CBOR (CTAP/WebAuthn Data)", "cbor (ctap/webauthn data)"):
        with pytest.raises(ValueError, match="clientDataHash"):
            encode_text.encode_payload_text('{"01": "AQ"}', fmt)


@pytest.mark.parametrize(("text", "error"), [("   ", "Encoder input is empty"), ("not-json", "expects a JSON document")])
def test_the_input_must_be_a_json_document(text, error):
    with pytest.raises(ValueError, match=error):
        encode_text.encode_payload_text(text, "json")


def test_a_format_that_is_no_text_is_refused():
    with pytest.raises(ValueError, match="Encoder format must be a string"):
        encode_text.encode_payload_text("{}", 123)


def test_pem_encoder_normalizes_the_label():
    pem_response = encode_handlers_basic._encode_pem_value({'value': {'hex': 'aabbccdd'}, 'pemLabel': ' demo cert '})
    assert pem_response['success'] is True
    assert 'BEGIN DEMO_CERT' in pem_response['data']['pem']


def test_encoder_response_keeps_the_qualifier_and_warnings():
    prepared = encode_handlers_basic._prepare_encoder_response('JSON', {'value': {'bytes': b'\x01\x02'}}, qualifier='encoded', warnings=['warn'])
    assert prepared['type'] == 'JSON (encoded)'
    assert prepared['malformed'] == ['warn']
    assert prepared['data']['value']['bytes'] == 'AQI'
