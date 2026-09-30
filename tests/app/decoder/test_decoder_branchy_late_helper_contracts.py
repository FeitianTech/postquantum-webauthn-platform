from __future__ import annotations

import base64

from server.app.decoder.decode import answer as decode_answer
from server.app.decoder.decode import cose_display
from server.app.decoder.decode import ctap as decode_ctap


def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return b"\x11" * 32 + bytes([flags]) + sign_count.to_bytes(4, "big")


def test_late_cose_and_base64_helpers_cover_fallback_and_conversion_branches():
    assert cose_display._resolve_cose_algorithm({"3": "-257"}) == "RS256 (RSA)"
    assert cose_display._resolve_cose_algorithm({"alg": "custom-alg"}) == "custom-alg"
    assert cose_display._resolve_cose_algorithm({}, {"publicKeyAlgorithm": -259}) == "RS512 (RSA)"
    assert cose_display._resolve_cose_algorithm({}, -999) == "COSE alg -999"
    assert cose_display._resolve_cose_algorithm({}, None) is None

    converted = cose_display._convert_cose_key_for_display([
        "AQI=",
        {"k": "AQI="},
        "not-base64$$",
    ])
    assert converted[0] == "0102"
    assert converted[1]["k"] == "0102"
    assert converted[2] == "not-base64$$"

    assert cose_display._decode_base64_field("++8") == b"\xfb\xef"
    assert cose_display._decode_base64_field("   ") is None


def test_binary_extract_helpers_cover_nested_hex_error_and_fallback(monkeypatch):
    assert decode_answer._extract_hex_from_binary({"binary": {"hex": "AABB"}}) == "AABB"

    monkeypatch.setattr(
        base64,
        "urlsafe_b64decode",
        lambda _value: (_ for _ in ()).throw(ValueError("invalid-base64")),
    )
    assert decode_answer._extract_bytes_from_binary({"hex": "ZZ", "raw": "%%%%"}) is None
    monkeypatch.undo()

    raw = base64.urlsafe_b64encode(b"\x01\x02").decode("ascii").rstrip("=")
    assert decode_answer._extract_bytes_from_binary({"raw": raw}) == b"\x01\x02"

    called: dict[str, object] = {}

    def _fake_extract(attestation_entry):
        called["entry"] = attestation_entry
        return b"\x99"

    monkeypatch.setattr(
        decode_answer,
        "_extract_authenticator_bytes_from_attestation",
        _fake_extract,
    )

    assert (
        decode_answer._extract_authenticator_bytes("not-a-mapping", {"raw": "AQI="})
        == b"\x99"
    )
    assert called["entry"] == {"raw": "AQI="}

    assert (
        decode_answer._extract_authenticator_bytes(
            {"authenticatorData": {"hex": "aa"}}, {"raw": "AQI="}
        )
        == b"\xaa"
    )


def test_try_decode_cbor_reports_trailing_bytes_and_padding_alike():
    # MAKE_CREDENTIAL, the integer 42, then two more bytes. Padding is reported
    # as well, as padding: nothing after the item goes unmentioned.

    result = decode_ctap._try_decode_cbor(b"\x01\x18\x2a\x11\x22", "hex")
    assert result["malformed"] == ["Trailing 2 byte(s) after CBOR payload."]
    assert result["decoded"]["ctap"]["trailingBytesHex"] == "1122"
    assert result["decoded"]["ctap"]["payloadLength"] == 2

    result_padding = decode_ctap._try_decode_cbor(b"\x01\x18\x2a\x00\xff", "hex")
    assert result_padding["decoded"]["ctap"]["paddingBytes"] == 2
    assert result_padding["malformed"] == [
        "Trailing 2 byte(s) after CBOR payload (all 0x00/0xff: HID report padding?)."
    ]
