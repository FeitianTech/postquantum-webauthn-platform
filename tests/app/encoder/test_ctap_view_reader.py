"""``decoder.encode.ctap_view_reader``: a CTAP view names one message the encoder builds, or is refused."""
from __future__ import annotations

import json

import pytest

from server.app.decoder.encode import text as encode_text

FRAMING = {"code": 1, "codeHex": "0x01", "kind": "command"}


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ({"ctapDecoded": {"unknown": {"x": 1}}}, "ctapDecoded.unknown is not a CTAP message the encoder builds"),
        ({"ctapDecoded": {}, "expandedJson": {"x": 1}}, "ctapDecoded names no CTAP message"),
        ({"ctap": FRAMING, "ctapDecoded": {"makeCredentialRequest": "not-a-map"}}, "ctapDecoded.makeCredentialRequest must be an object"),
        (
            {"ctap": FRAMING, "ctapDecoded": {"makeCredentialRequest": {}, "getAssertionRequest": {}}},
            "ctapDecoded holds 2 messages",
        ),
        ({"expandedJson": {"x": 1}, "ctap": {"code": 2}}, "expandedJson is encoded as the CTAP message ctap.message names; it names none"),
    ],
)
def test_a_view_that_names_no_single_message_is_refused_saying_why(value, error):
    with pytest.raises(ValueError, match=error):
        encode_text.encode_payload_text(json.dumps(value), "CBOR")
