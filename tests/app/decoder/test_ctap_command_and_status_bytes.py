"""The decoder reads the CTAP command or status byte a message starts with.

It used to know two commands and one status, so a single-byte error response
such as 0x31 (PIN_INVALID) was handed to the CBOR parser as data, or read as
the ASCII digit "1" and shown as JSON. The byte sets are fido2's own:
``Ctap2.CMD`` and ``CtapError.ERR``.

A request is a command byte and its CBOR parameters; a response is a status
byte, followed by CBOR only on success. So a byte with a payload after it is a
command (or 0x00, SUCCESS); a byte alone is an error status or a command sent
without parameters, and when the byte names both, the decoder says so.
"""
from __future__ import annotations

import base64

import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from server.app.decoder import decode_payload_text
from server.app.decoder.decode import ctap

_COMMAND_CODES = {int(command) for command in Ctap2.CMD}
_ERROR_STATUSES = [status for status in CtapError.ERR if status != CtapError.ERR.SUCCESS]


def test_a_lone_pin_invalid_byte_is_the_pin_invalid_status():
    prefix, payload = ctap._extract_ctap_prefix(b"\x31")

    assert prefix == {
        "code": 0x31,
        "codeHex": "0x31",
        "kind": "status",
        "status": "PIN_INVALID",
        "meaning": "PIN_INVALID status",
    }
    assert payload == b""


@pytest.mark.parametrize("payload", ["31", "0x31", base64.b64encode(b"\x31").decode("ascii")])
def test_api_decode_shows_a_pin_invalid_response_as_that_status(client, payload):
    response = client.post("/api/decode", json={"payload": payload})

    assert response.status_code == 200
    body = response.get_json()
    assert body["type"] == "CBOR (PIN_INVALID status)"
    assert body["data"]["ctap"]["status"] == "PIN_INVALID"
    assert body["data"]["ctap"]["kind"] == "status"


@pytest.mark.parametrize("status", _ERROR_STATUSES, ids=lambda status: status.name)
def test_every_fido2_error_status_decodes_as_a_lone_byte(status):
    result = decode_payload_text(bytes([status]).hex())
    ctap_info = result["data"]["ctap"]

    assert ctap_info["status"] == status.name
    if int(status) in _COMMAND_CODES:
        assert ctap_info["kind"] == "command or status"
        assert ctap_info["command"] == Ctap2.CMD(int(status)).name
    else:
        assert ctap_info["kind"] == "status"
        assert result["type"] == f"CBOR ({status.name} status)"


@pytest.mark.parametrize("command", list(Ctap2.CMD), ids=lambda command: command.name)
def test_every_fido2_command_is_named_when_parameters_follow(command):
    prefix, payload = ctap._extract_ctap_prefix(bytes([command]) + cbor.encode({1: 1}))

    assert prefix is not None
    assert prefix["kind"] == "command"
    assert prefix["command"] == command.name
    assert prefix["meaning"] == f"{command.name} command"
    assert payload == cbor.encode({1: 1})


def test_a_lone_byte_that_is_both_a_command_and_a_status_says_so():
    prefix, _ = ctap._extract_ctap_prefix(b"\x04")

    assert prefix["kind"] == "command or status"
    assert prefix["command"] == "GET_INFO"
    assert prefix["status"] == "INVALID_SEQ"
    assert prefix["meaning"] == "GET_INFO command or INVALID_SEQ status"


def test_a_lone_parameterless_command_is_that_command():
    prefix, _ = ctap._extract_ctap_prefix(b"\x07")

    assert prefix["kind"] == "command"
    assert prefix["command"] == "RESET"


def test_a_two_digit_number_that_is_not_one_cbor_item_is_still_json():
    # 0x99 announces a two-byte array length; the other reading is named.
    result = decode_payload_text("99")

    assert result["type"] == "JSON"
    assert result["data"]["json"] == 99
    assert [finding["alsoValidAs"] for finding in result["findings"]] == ["hex"]


def test_a_two_digit_number_that_is_one_cbor_item_is_hex_and_says_so():
    # 0x10 is no CTAP code, but it is the CBOR integer 16 (ambiguous_input.py).
    result = decode_payload_text("10")

    assert result["type"] == "CBOR"
    assert result["data"]["decodedValue"] == 16
    assert [finding["alsoValidAs"] for finding in result["findings"]] == ["json"]


def test_an_error_status_never_carries_a_payload():
    prefix, payload = ctap._extract_ctap_prefix(b"\x31\xa0")

    assert prefix is None
    assert payload == b"\x31\xa0"


def test_a_client_pin_command_is_named():
    result = decode_payload_text((b"\x06" + cbor.encode({1: 2, 2: 1})).hex())

    assert result["data"]["ctap"]["command"] == "CLIENT_PIN"
    assert result["type"].startswith("CBOR (CLIENT_PIN command")


def test_the_encoder_prefixes_ctap_messages_with_fido2_codes():
    from server.app.decoder.encode import constants

    assert constants._CTAP_PREFIX_DETAILS == {
        "makeCredentialRequest": (int(Ctap2.CMD.MAKE_CREDENTIAL), "command"),
        "getAssertionRequest": (int(Ctap2.CMD.GET_ASSERTION), "command"),
        "makeCredentialResponse": (int(CtapError.ERR.SUCCESS), "status"),
        "getAssertionResponse": (int(CtapError.ERR.SUCCESS), "status"),
    }


@pytest.mark.parametrize("lenient", [False, True])
def test_a_command_byte_before_bytes_that_are_not_cbor_is_read_as_the_head_of_one_item(lenient):
    # h'ab': 0x41 is a one-byte byte string's head and the CREDENTIAL_MGMT_PRE
    # command byte. Read as the command, what follows (0xab) is not CBOR, and a
    # well-formed item was reported as "Not well-formed CBOR".
    result = decode_payload_text("41ab", lenient=lenient)

    assert result["type"] == "CBOR"
    assert result["data"]["decodedValue"] == "ab"
    (finding,) = [finding for finding in result["findings"] if finding["code"] == "ctap-prefix-not-read"]
    assert (finding["category"], finding["offset"], finding["path"]) == ("input", 0, "$")
    assert finding["message"].startswith("0x41 is also the CREDENTIAL_MGMT_PRE command byte")


@pytest.mark.parametrize(
    ("text", "type_label"),
    [
        ("4100", "CBOR (CREDENTIAL_MGMT_PRE command)"),  # both readings parse: the command's is kept
        ("41a0", "CBOR (CREDENTIAL_MGMT_PRE command)"),
        ("00a0", "CBOR (SUCCESS status)"),
        ("0101", "CBOR (MAKE_CREDENTIAL command)"),
        ("01", "CBOR (MAKE_CREDENTIAL command or INVALID_COMMAND status)"),  # a lone byte stays a lone byte
        ("04", "CBOR (GET_INFO command or INVALID_SEQ status)"),
        ("07", "CBOR (RESET command)"),
        ("40", "CBOR (BIO_ENROLLMENT_PRE command or UNAUTHORIZED_PERMISSION status)"),
    ],
)
def test_a_command_byte_whose_payload_parses_is_still_read_as_the_command(text, type_label):
    result = decode_payload_text(text)

    assert result["type"] == type_label
    assert "ctap-prefix-not-read" not in [finding["code"] for finding in result["findings"]]
