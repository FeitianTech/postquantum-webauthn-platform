"""``decoder.decode.ctap``: a CTAP message, with its command or status byte, as the decoder reads it.

Nothing after the item goes unmentioned, and what the authenticator sent is shown as sent.
"""

from __future__ import annotations

import hashlib

import cbor2
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import ctap as decode_ctap


def _attested_auth_data(sign_count: int) -> bytes:
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential = AttestedCredentialData.create(bytes.fromhex("00112233445566778899aabbccddeeff"), b"ctap-credential", cose_key)
    return bytes(
        AuthenticatorData.create(
            hashlib.sha256(b"example.com").digest(), AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, sign_count, credential
        )
    )


def test_bytes_after_the_item_are_reported_and_padding_as_padding():
    # MAKE_CREDENTIAL, the integer 42, then two more bytes.
    trailing = decode_ctap._try_decode_cbor(b"\x01\x18\x2a\x11\x22", "hex")
    padding = decode_ctap._try_decode_cbor(b"\x01\x18\x2a\x00\xff", "hex")

    assert trailing["malformed"] == ["Trailing 2 byte(s) after CBOR payload."]
    assert (trailing["decoded"]["ctap"]["trailingBytesHex"], trailing["decoded"]["ctap"]["payloadLength"]) == ("1122", 2)
    assert padding["decoded"]["ctap"]["paddingBytes"] == 2
    assert padding["malformed"] == ["Trailing 2 byte(s) after CBOR payload (all 0x00/0xff: HID report padding?)."]


def test_a_make_credential_response_keeps_its_att_stmt_as_sent_with_bytes_after_it_reported():
    response = {1: "packed", 2: _attested_auth_data(2), 3: {"alg": -7, "sig": b"\x01\x02"}}

    result = decode_ctap._try_decode_cbor(b"\x00" + cbor.encode(response) + b"\xaa\xbb\xcc\xdd", "hex")

    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    # The bytes after it are no signature.
    assert "signatureLength" not in decoded["ctap"]
    assert decoded["ctapDecoded"]["makeCredentialResponse"]["3 (attStmt)"] == {"alg": -7, "sig": "0102"}
    assert result["malformed"]


def test_a_status_prefixed_map_of_no_response_shape_is_not_named_a_response():
    # A status byte says "response", not which command it answers; authData alone is neither shape.
    result = decode_ctap._try_decode_cbor(b"\x00" + cbor.encode({"authData": _attested_auth_data(3)}) + b"\x12\x34", "hex")

    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    assert "expandedJson" not in decoded
    assert "ctapDecoded" not in decoded
    assert "decodedValue" in decoded
    assert result["malformed"]


def test_try_decode_cbor_interprets_prefixed_get_assertion_request_payload():
    map_payload = cbor2.dumps({1: "example.com", 2: b"\x22" * 32})
    data = b"\x02" + map_payload

    result = decode_ctap._try_decode_cbor(data, "hex")

    assert result is not None
    assert result["format"] == "CBOR"
    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "command"
    assert list(decoded["ctapDecoded"]) == ["getAssertionRequest"]
    assert decoded["ctapDecoded"]["getAssertionRequest"]["1 (rpId)"] == "example.com"
    assert decoded["expandedJson"]["2 (clientDataHash)"] == (b"\x22" * 32).hex()


def test_extract_ctap_prefix_handles_empty_command_status_and_unknown_codes():
    prefix, remaining = decode_ctap._extract_ctap_prefix(b"")
    assert prefix is None
    assert remaining == b""

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x01\xaa\xbb")
    assert prefix == {
        "code": 1,
        "codeHex": "0x01",
        "command": "MAKE_CREDENTIAL",
        "meaning": "MAKE_CREDENTIAL command",
        "kind": "command",
    }
    assert remaining == b"\xaa\xbb"

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x00\xcc")
    assert prefix == {
        "code": 0,
        "codeHex": "0x00",
        "status": "SUCCESS",
        "meaning": "SUCCESS status",
        "kind": "status",
    }
    assert remaining == b"\xcc"

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x7f\xdd")
    assert prefix is None
    assert remaining == b"\x7f\xdd"


def test_is_padding_bytes_distinguishes_padding_from_content():
    assert decode_ctap._is_padding_bytes(b"") is True
    assert decode_ctap._is_padding_bytes(b"\x00\xff\x00") is True
    assert decode_ctap._is_padding_bytes(b"\x00\x01\xff") is False


def test_try_decode_cbor_returns_none_for_empty_data():
    assert decode_ctap._try_decode_cbor(b"", "hex") is None


def test_try_decode_cbor_reports_bytes_after_the_first_item_as_trailing():
    payload = cbor2.dumps({"a": 1}) + cbor2.dumps(2) + cbor2.dumps(3)

    result = decode_ctap._try_decode_cbor(payload, "base64url")

    assert result["format"] == "CBOR"
    assert result["inputEncoding"] == "base64url"
    assert result["decoded"]["decodedValue"] == {"a": 1}
    assert result["malformed"] == ["Trailing 2 byte(s) after CBOR payload."]


def test_try_decode_cbor_handles_ctap_prefix_without_payload():
    result = decode_ctap._try_decode_cbor(b"\x01", "hex")

    assert result is not None
    assert result["format"] == "CBOR"
    assert result["decoded"]["decodedValue"]["summary"] == "Empty CBOR payload"
    # Alone, 0x01 is MAKE_CREDENTIAL without parameters or the INVALID_COMMAND status.
    assert result["decoded"]["ctap"]["kind"] == "command or status"
    assert result["decoded"]["ctap"]["payloadLength"] == 0


def test_try_decode_cbor_reports_ctap_padding_bytes_as_padding():
    payload = b"\x01" + cbor2.dumps({"a": 1}) + b"\x00\xff"

    result = decode_ctap._try_decode_cbor(payload, "base64url")

    assert result["format"] == "CBOR"
    ctap = result["decoded"]["ctap"]
    assert ctap["kind"] == "command"
    assert ctap["paddingBytes"] == 2
    trailing = [finding["message"] for finding in result["findings"] if finding["code"] == "trailing-bytes"]
    assert trailing == ["Trailing 2 byte(s) after CBOR payload (all 0x00/0xff: HID report padding?)."]
