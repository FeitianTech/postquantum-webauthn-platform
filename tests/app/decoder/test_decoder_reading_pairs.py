"""Inputs that two of the decoder's readings both read whole: which it takes, and whether it says so.

``decode/ambiguous_input.py`` lists the readings in order and every pair of
them that can both read one input. Each row here is one such input.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, encode_payload_text

# 37 bytes of JSON text whose byte 32, "1" (0x31), is authenticator-data flags without AT or ED.
_JSON_37 = ('"' + "z" * 31 + "1" + "zzz" + '"').encode()
# A getInfo response of 37 bytes: SUCCESS, {1: ["FIDO_2_0"], 3: aaguid, "1": 1, 99: 2}.
_GET_INFO_37 = bytes.fromhex("00a4018168464944" "4f5f325f300350" + "00" * 16 + "6131011863" "02")
# {1: "x", 2: h'01', 3: {}}: a makeCredential response's shape and a getAssertion request's.
_BARE_MAP = "a3" "016178" "024101" "03a0"
_CREDENTIAL_AND_CLIENT_DATA = json.dumps(
    {"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "id": "x", "response": {"signature": "AAAA"}}
)

_LONE = "a CTAP command or status byte"
_MESSAGE = "a CTAP command or status byte and one CBOR item"
_BARE = "a makeCredential response with no CTAP command or status byte"

PAIRS = [
    # (name, input, type read as, reading taken, the others named)
    ("a lone CTAP byte, or the CBOR integer 5", "05", "CBOR (TIMEOUT status)", _LONE, ["one CBOR item"]),
    (
        "a lone CTAP byte, or the CBOR integer -18, or the JSON text 1",
        "31",
        "CBOR (PIN_INVALID status)",
        _LONE,
        ["JSON text", "one CBOR item"],
    ),
    ("CREDENTIAL_MGMT_PRE and 0, or the byte string h'00'", "4100", "CBOR (CREDENTIAL_MGMT_PRE command)", _MESSAGE,
     ["one CBOR item"]),
    ("the JSON text 85, or the CBOR integer -54", "3835", "JSON", "JSON text", ["one CBOR item"]),
    ("CREDENTIAL_MGMT and -18, or the JSON text 1 after a newline", "0a31", "JSON", "JSON text", [_MESSAGE]),
    # One item (or CTAP message) is read as that, before authenticator data.
    ("one CBOR item, or authenticator data", "9823" + "01" * 35, "CBOR", "one CBOR item", ["authenticator data"]),
    ("a getInfo response, or authenticator data", _GET_INFO_37.hex(), "CBOR (SUCCESS status; GetInfo response)",
     _MESSAGE, ["authenticator data"]),
    ("JSON text, or authenticator data", _JSON_37.hex(), "JSON", "JSON text", ["authenticator data"]),
    ("a makeCredential response or a getAssertion request, with no CTAP byte", _BARE_MAP,
     "CBOR (MakeCredential response)", _BARE, ["a getAssertion request", "a CBOR map that is no CTAP message"]),
    ("a PublicKeyCredential, or client data", _CREDENTIAL_AND_CLIENT_DATA, "PublicKeyCredential",
     "a PublicKeyCredential", ["client data"]),
    ("hexadecimal (ea e0), or base64 (the text item \"4\")", "eAE0", "CBOR", "hex", ["base64"]),
]


def _named(result: dict) -> list[tuple[str, str]]:
    """What the ambiguous-input findings name, besides the text's JSON-number or hexadecimal reading."""

    return [
        (finding["readAs"], finding["alsoValidAs"])
        for finding in result["findings"]
        if finding["code"] == "ambiguous-input" and {finding["readAs"], finding["alsoValidAs"]} != {"hex", "json"}
    ]


@pytest.mark.parametrize(
    ("name", "text", "read_as", "taken", "others"), PAIRS, ids=[row[0] for row in PAIRS]
)
def test_each_pair_is_read_one_way_and_every_other_reading_is_named(name, text, read_as, taken, others):
    result = decode_payload_text(text)

    assert result["type"] == read_as
    assert _named(result) == [(taken, other) for other in others]
    for finding in result["findings"]:
        if finding["code"] == "ambiguous-input" and finding["alsoValidAs"] in others:
            assert finding["message"].startswith(f"the input is also {finding['alsoValidAs']}")
            assert finding["message"].endswith("which comes first in the decoder's order of readings (decode/ambiguous_input.py)")


# {1: ["FIDO_2_0"], 3: aaguid, 5: 1200}, a getInfo response of 34 bytes; padded with zero bytes to 37,
# after SUCCESS or with no CTAP byte, byte 32 (0x19, 0x04) has neither AT nor ED.
_GET_INFO_34 = "a3" "018168" + b"FIDO_2_0".hex() + "0350" "2fc0579f811347eab116bb5a8db9202a" "051904b0"
_AND_BYTES = ("a CTAP message and the bytes after it", "authenticator data")
_PADDED_TO_37 = [
    # (name, input, type read as, the padding kept in data.ctap, what is named)
    ("after SUCCESS", "00" + _GET_INFO_34 + "0000", "CBOR (SUCCESS status; GetInfo response)", "0000", [_AND_BYTES]),
    (
        "with no CTAP byte",
        _GET_INFO_34 + "000000",
        "CBOR (GetInfo response)",
        "000000",
        [("a getInfo response with no CTAP command or status byte", "a CBOR map that is no CTAP message"), _AND_BYTES],
    ),
]


@pytest.mark.parametrize(
    ("name", "text", "read_as", "padding", "named"), _PADDED_TO_37, ids=[row[0] for row in _PADDED_TO_37]
)
def test_a_ctap_message_padded_to_37_bytes_is_read_as_that_message_and_authenticator_data_is_named(
    name, text, read_as, padding, named
):
    result = decode_payload_text(text)

    assert len(bytes.fromhex(text)) == 37
    assert result["type"] == read_as
    assert result["data"]["ctap"]["trailingBytesHex"] == padding
    assert _named(result) == named
    assert encode_payload_text(json.dumps(result["data"]), "CBOR")["data"]["binary"]["hex"] == text


def test_a_command_byte_before_a_map_not_its_requests_shape_padded_to_37_bytes_stays_authenticator_data():
    # 0x01 (MAKE_CREDENTIAL) and {} are how 1 rpIdHash in 65536 starts: a command byte alone does not make
    # the bytes after the map a CTAP message's.
    result = decode_payload_text("01a0" + "00" * 35)

    assert result["type"] == "Authenticator data"
    assert _named(result) == []
