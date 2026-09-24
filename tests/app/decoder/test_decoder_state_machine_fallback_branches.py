from __future__ import annotations

import pytest


def test_lenient_uint_and_decode_state_machine_edges():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._lenient_read_uint(24, b"", 0) == (0, 0)
    assert decode_module._lenient_read_uint(25, b"\x00", 0) == (0, 1)
    assert decode_module._lenient_read_uint(25, b"\x00\x02", 0) == (2, 2)
    assert decode_module._lenient_read_uint(26, b"\x00", 0) == (0, 1)
    assert decode_module._lenient_read_uint(26, b"\x00\x00\x00\x02", 0) == (2, 4)
    assert decode_module._lenient_read_uint(27, b"\x00", 0) == (0, 1)
    assert decode_module._lenient_read_uint(27, b"\x00\x00\x00\x00\x00\x00\x00\x02", 0) == (2, 8)
    assert decode_module._lenient_read_uint(28, b"", 0) == (28, 0)
    assert decode_module._lenient_read_uint(31, b"", 0) == (0, 0)

    assert decode_module._lenient_decode_from(b"\x5f\x01\xff") == (b"", 2)
    assert decode_module._lenient_decode_from(b"\x7f\x01\xff") == ("", 3)

    replacement_text, replacement_offset = decode_module._lenient_decode_from(b"\x62\xff\xff")
    assert replacement_offset == 3
    assert "\ufffd" in replacement_text

    assert decode_module._lenient_decode_from(b"\x9f\xf6") == ([], 2)
    assert decode_module._lenient_decode_from(b"\x81") == ([], 1)

    assert decode_module._lenient_decode_from(b"\xbf\x01") == ({}, 2)
    assert decode_module._lenient_decode_from(b"\xa1") == ({}, 1)
    assert decode_module._lenient_decode_from(b"\xa1\x01") == ({}, 2)
    assert decode_module._lenient_decode_from(b"\xa1\x81\x01\x02") == ({"[1]": 2}, 4)
    assert decode_module._lenient_decode_from(b"\xbf\x81\x01\x02\xff") == ({"[1]": 2}, 5)

    assert decode_module._lenient_decode_from(b"\xc1\x01") == ({"tag": 1, "value": 1}, 2)
    assert decode_module._lenient_decode_from(b"\xf4") == (False, 1)
    assert decode_module._lenient_decode_from(b"\xf6") == (None, 1)
    assert decode_module._lenient_decode_from(b"\xf7") == (None, 1)
    assert decode_module._lenient_decode_from(b"\xf8") == (0, 2)
    assert decode_module._lenient_decode_from(b"\xf8\x2a") == (42, 2)
    assert decode_module._lenient_decode_from(b"\xf9\x00") == (0.0, 2)
    assert decode_module._lenient_decode_from(b"\xfa\x00") == (0.0, 2)
    assert decode_module._lenient_decode_from(b"\xfb\x00\x00") == (0.0, 3)
    assert decode_module._lenient_decode_from(b"\xff") == (31, 1)


def test_try_decode_cbor_returns_none_when_no_cbor_structures(monkeypatch, ctap):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        ctap,
        "_decode_cbor_sequence",
        lambda _payload: ([], [], 0, b""),
    )

    assert decode_module._try_decode_cbor(b"\xa1", "hex") is None


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
