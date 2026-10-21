"""``decoder.decode.ctap_self_check``: the decoder rebuilds each CTAP view it shows and compares."""
from __future__ import annotations

import cbor2

from server.app.decoder import item_budget
from server.app.decoder.decode import ctap_self_check
from server.app.decoder.decode.text import decode_payload_text


def test_the_view_is_rebuilt_without_counting_what_the_rebuild_reads():
    # A getInfo response whose extension "abcd" is text that looks like hex: its
    # view spells it with its type, which the rebuild reads back as EDN.
    data = b"\x00" + cbor2.dumps({1: ["FIDO_2_0"], 2: ["abcd"], 3: bytes(16)}, canonical=True)
    answer = decode_payload_text(data.hex())["data"]
    view = answer["ctapDecoded"]["getInfoResponse"]
    assert view["2 (extensions)"] == ['"abcd" (text)']

    with item_budget.limit(0) as budget:
        assert ctap_self_check.check("getInfoResponse", view, answer["ctap"], data, []) is None
    assert budget.used == 0
