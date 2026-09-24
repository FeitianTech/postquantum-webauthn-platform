from __future__ import annotations

import pytest


def test_format_cbor_summary_falls_back_to_raw_decoded_block():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = decode_module._format_cbor_summary({"decoded": {"foo": "bar"}})
    assert "CBOR:\t" in lines
    assert any('"foo": "bar"' in line for line in lines)


def test_build_decoder_payload_appends_request_and_response_qualifiers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = decode_module._build_decoder_payload(
        {
            "format": "CBOR",
            "decoded": {
                "ctap": {"meaning": "Status meaning"},
                "ctapDecoded": {"makeCredentialRequest": {"rp": "example.com"}},
                "expandedJson": {"attStmt": {"sig": "aa"}, "signature": "bb"},
            },
        }
    )

    assert payload["success"] is True
    assert "MakeCredential request" in payload["type"]
    assert "MakeCredential response" in payload["type"]
    assert "GetAssertion response" in payload["type"]
