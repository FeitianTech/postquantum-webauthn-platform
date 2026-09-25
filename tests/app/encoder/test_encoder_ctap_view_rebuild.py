"""A CTAP view whose input is not what the encoder writes: not in CTAP2 canonical form, or read leniently.

The encoder writes CTAP2 canonical CBOR. A message that was not -- a head wider
than its value needs, keys out of order -- or that the lenient parser read
past damage, has a view that cannot give back its bytes. The decoder checks its
own view (``decode/ctap_self_check.py``) and marks it; the encoder refuses it
by that mark, and the item's EDN gives the bytes back.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, edn, encode_payload_text
from tests.fido2.client.test_client import _MC_RESP

_AUTH_DATA = "00" * 32 + "01" + "00000001"
NOT_CANONICAL = {
    # The fido2 client's captured makeCredential response: authData's head is 59 00c4, not 58 c4.
    "a head wider than its value needs": _MC_RESP,
    # makeCredential members 2 before 1.
    "keys out of order": b"\x00" + edn.encode(f'{{2: h\'{_AUTH_DATA}\', 1: "none", 3: {{}}}}'),
}


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (NOT_CANONICAL["a head wider than its value needs"], "non-shortest-length at offset 10"),
        (NOT_CANONICAL["keys out of order"], "map-key-order at offset"),
    ],
    ids=list(NOT_CANONICAL),
)
def test_the_view_of_a_message_not_in_canonical_form_is_marked_and_refused(message, reason):
    decoded = decode_payload_text(message.hex())["data"]

    assert decoded["ctap"]["notRebuildable"].startswith(
        "the input is not what the encoder writes, well-formed CTAP2 canonical CBOR: "
    )
    assert reason in decoded["ctap"]["notRebuildable"]
    with pytest.raises(ValueError, match=r"does not give back the bytes it was read from \(the input is not what the encoder writes"):
        encode_payload_text(json.dumps(decoded), "CBOR")
    # Its EDN is exact.
    code = decoded["ctap"]["code"]
    prefix = b"" if code is None else bytes([code])
    assert prefix + bytes.fromhex(encode_payload_text(decoded["edn"], "EDN")["data"]["binary"]["hex"]) == message
    # Without the mark, the view is written in canonical form: other bytes, asked for.
    unmarked = {**decoded, "ctap": {key: value for key, value in decoded["ctap"].items() if key != "notRebuildable"}}
    assert bytes.fromhex(encode_payload_text(json.dumps(unmarked), "CBOR")["data"]["binary"]["hex"]) != message


def test_a_view_the_lenient_parser_read_past_damage_is_marked():
    # {1: "none", 2: authData, 3: {}} with the text "none" sent as (_ "no", 1, "ne"): the 1 is skipped.
    message = b"\x00" + edn.encode(f'{{1: "none", 2: h\'{_AUTH_DATA}\', 3: {{}}}}')
    damaged = message.replace(bytes.fromhex("646e6f6e65"), bytes.fromhex("7f626e6f0162" "6e65ff"))

    decoded = decode_payload_text(damaged.hex(), lenient=True)["data"]

    assert "invalid-indefinite-chunk at offset" in decoded["ctap"]["notRebuildable"]
    with pytest.raises(ValueError, match="does not give back the bytes it was read from"):
        encode_payload_text(json.dumps(decoded), "CBOR")


def test_a_canonical_message_is_not_marked():
    message = b"\x00" + edn.encode(f'{{1: "none", 2: h\'{_AUTH_DATA}\', 3: {{}}}}')

    decoded = decode_payload_text(message.hex())["data"]

    assert "notRebuildable" not in decoded["ctap"]
    assert encode_payload_text(json.dumps(decoded), "CBOR")["data"]["binary"]["hex"] == message.hex()
