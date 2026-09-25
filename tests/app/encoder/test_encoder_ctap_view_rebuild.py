"""A CTAP view whose input is not what the encoder writes: not in CTAP2 canonical form, or read leniently.

The encoder writes CTAP2 canonical CBOR. A message that was not -- a head wider
than its value needs, keys out of order -- or that the lenient parser read
past damage, has a view that cannot give back its bytes.
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


@pytest.mark.parametrize("message", list(NOT_CANONICAL.values()), ids=list(NOT_CANONICAL))
def test_the_view_of_a_message_not_in_canonical_form_encodes_to_other_bytes_without_a_word(message):
    decoded = decode_payload_text(message.hex())["data"]

    encoded = bytes.fromhex(encode_payload_text(json.dumps(decoded), "CBOR")["data"]["binary"]["hex"])

    assert encoded != message
    assert "notRebuildable" not in decoded["ctap"]
