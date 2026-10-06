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
