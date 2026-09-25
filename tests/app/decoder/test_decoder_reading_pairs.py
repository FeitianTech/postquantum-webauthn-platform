"""Inputs that two of the decoder's readings both read whole: which it takes, and whether it says so.

``decode/ambiguous_input.py`` lists the readings in order and every pair of
them that can both read one input. Each row here is one such input.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text

# 37 bytes of JSON text whose byte 32, "1" (0x31), is authenticator-data flags without AT or ED.
_JSON_37 = ('"' + "z" * 31 + "1" + "zzz" + '"').encode()
# A getInfo response of 37 bytes: SUCCESS, {1: ["FIDO_2_0"], 3: aaguid, "1": 1, 99: 2}.
_GET_INFO_37 = bytes.fromhex("00a4018168464944" "4f5f325f300350" + "00" * 16 + "6131011863" "02")
# {1: "x", 2: h'01', 3: {}}: a makeCredential response's shape and a getAssertion request's.
_BARE_MAP = "a3" "016178" "024101" "03a0"
_CREDENTIAL_AND_CLIENT_DATA = json.dumps(
    {"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "id": "x", "response": {"signature": "AAAA"}}
)

PAIRS = [
    # (name, input, type read as today)
    ("a lone CTAP byte, or the CBOR integer 5", "05", "CBOR (TIMEOUT status)"),
    ("a lone CTAP byte, or the CBOR integer -18, or the JSON text 1", "31", "CBOR (PIN_INVALID status)"),
    ("CREDENTIAL_MGMT_PRE and 0, or the byte string h'00'", "4100", "CBOR (CREDENTIAL_MGMT_PRE command)"),
    ("the JSON text 85, or the CBOR integer -54", "3835", "JSON"),
    ("CREDENTIAL_MGMT and -18, or the JSON text 1 after a newline", "0a31", "JSON"),
    ("one CBOR item, or authenticator data", "9823" + "01" * 35, "Authenticator data"),
    ("a getInfo response, or authenticator data", _GET_INFO_37.hex(), "Authenticator data"),
    ("JSON text, or authenticator data", _JSON_37.hex(), "JSON"),
    ("a makeCredential response or a getAssertion request, with no CTAP byte", _BARE_MAP, "CBOR (MakeCredential response)"),
    ("a PublicKeyCredential, or client data", _CREDENTIAL_AND_CLIENT_DATA, "PublicKeyCredential"),
    ("hexadecimal (ea e0), or base64 (the text item \"4\")", "eAE0", "CBOR"),
]


def _named_alternatives(result: dict) -> list[str]:
    """What the ambiguous-input findings name besides the text's JSON-number or hexadecimal reading."""

    return [
        finding["alsoValidAs"]
        for finding in result["findings"]
        if finding["code"] == "ambiguous-input" and finding["alsoValidAs"] not in ("json", "hex")
    ]


@pytest.mark.parametrize(("name", "text", "read_as"), PAIRS, ids=[name for name, _text, _read in PAIRS])
def test_each_pair_is_read_one_way_and_the_other_reading_is_not_named(name, text, read_as):
    result = decode_payload_text(text)

    assert result["type"] == read_as
    assert _named_alternatives(result) == []
