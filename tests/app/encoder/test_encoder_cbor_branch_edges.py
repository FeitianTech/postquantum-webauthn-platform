import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_make_credential_request_payload() -> dict:
    # A view's members by number, its values in the view's spelling: bytes as hex.
    return {
        "1 (clientDataHash)": (b"\x11" * 32).hex(),
        "2 (rp)": {"id": "example.com", "name": "Example"},
        "3 (user)": {"id": b"user".hex(), "name": "alice", "displayName": "Alice"},
        "4 (pubKeyCredParams)": [{"alg": -7, "type": "public-key"}],
    }


def test_encode_cbor_value_prefers_ctap_decoded_when_present():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    parsed = {
        "ctap": {"code": 1, "codeHex": "0x01", "kind": "command"},
        "ctapDecoded": {"makeCredentialRequest": _make_make_credential_request_payload()},
    }

    result = encode_module._encode_cbor_value(parsed)
    assert result["success"] is True
    assert "encoded makeCredentialRequest" in result["type"]
    assert result["data"]["ctap"]["code"] == 1


def test_encode_cbor_value_reads_ctap_only_from_an_explicit_view():
    encode_module = pytest.importorskip("server.app.decoder.encode")
    expanded = {"1 (rpId)": "example.com", "2 (clientDataHash)": (b"\x22" * 32).hex()}

    # A ctapDecoded naming something the encoder does not build is refused, not skipped.
    with pytest.raises(ValueError, match="ctapDecoded.unknown is not a CTAP message the encoder builds"):
        encode_module._encode_cbor_value({"ctapDecoded": {"unknown": {"x": 1}}})
    # An empty one is refused too, rather than falling through to guessing.
    with pytest.raises(ValueError, match="ctapDecoded names no CTAP message"):
        encode_module._encode_cbor_value({"ctapDecoded": {}, "expandedJson": expanded})

    # expandedJson is a CTAP view beside its framing, which names the message it is...
    framing = {"code": 2, "codeHex": "0x02", "kind": "command", "message": "getAssertionRequest"}
    result = encode_module._encode_cbor_value({"expandedJson": expanded, "ctap": framing})
    assert result["success"] is True
    assert "getAssertionRequest" in result["type"]
    with pytest.raises(ValueError, match="expandedJson is encoded as the CTAP message ctap.message names; it names none"):
        encode_module._encode_cbor_value({"expandedJson": {"x": 1}, "ctap": {"code": 2}})

    # ... and without it, just a map.
    plain = encode_module._encode_cbor_value({"expandedJson": {"rpId": "example.com"}})
    assert plain["type"] == "CBOR (canonical) (encoded)"
    assert "ctap" not in plain["data"]


def test_encode_cbor_value_non_ctap_path_and_normalize_format_empty_error():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    result = encode_module._encode_cbor_value([1, 2, 3])
    assert result["success"] is True
    assert result["type"].startswith("CBOR")
    assert "decodedValue" in result["data"]

    with pytest.raises(ValueError, match="must be provided"):
        encode_module._normalize_encoding_format("   ")


def test_extract_ctap_numeric_payload_salvages_labeled_nested_candidate():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    payload = {
        "bad": {"field": "value"},
        "nested": {
            "01 (rpId)": "example.com",
            "02 (clientDataHash)": _b64url(b"\x33" * 32),
        },
    }

    numeric, kind = encode_module._extract_ctap_numeric_payload(payload)
    assert kind == "getAssertionRequest"
    assert set(numeric) == {1, 2}


def test_unsigned_integer_and_major_length_boundaries_cover_all_encoding_sizes():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._encode_unsigned_integer(0, 23) == bytes([23])
    assert encode_module._encode_unsigned_integer(0, 24) == b"\x18\x18"
    assert encode_module._encode_unsigned_integer(0, 255) == b"\x18\xff"
    assert encode_module._encode_unsigned_integer(0, 256) == b"\x19\x01\x00"
    assert encode_module._encode_unsigned_integer(0, 65536) == b"\x1a\x00\x01\x00\x00"
    assert encode_module._encode_unsigned_integer(0, 4294967296) == b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00"

    assert encode_module._encode_major_type_with_length(5, 2) == bytes([0xA2])


def test_canonical_float_handles_double_fallback_for_large_value():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    encoded = encode_module._encode_canonical_float(1e300)
    assert encoded.startswith(b"\xfb")
