from __future__ import annotations

from server.app.decoder.decode import ctap_classify as decode_ctap_classify


def test_remaining_mapping_and_auth_data_format_helpers():
    mapping = {1: "packed", 2: b"\xaa\xbb"}
    assert decode_ctap_classify._extract_mapping_string(mapping, (1, "fmt")) == "packed"
    assert decode_ctap_classify._extract_mapping_bytes(mapping, (2, "authData")) == b"\xaa\xbb"
