"""A getInfo response as the decoder shows it (``ctapDecoded.getInfoResponse``), and as the encoder reads it back."""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, edn, encode_payload_text

# SUCCESS, then {1: ["FIDO_2_0"], 3: aaguid, 4: {"rk": true}, 99: 2, "1": 1}.
_GET_INFO = "00" + edn.encode('{1: ["FIDO_2_0"], 3: h\'' + "00" * 16 + '\', 4: {"rk": true}, 99: 2, "1": 1}').hex()


def test_the_view_puts_what_the_members_mean_in_place_of_what_they_hold():
    view = decode_payload_text(_GET_INFO)["data"]["ctapDecoded"]["getInfoResponse"]

    assert view["3 (aaguid)"] == {"hex": "00" * 16, "guid": "00000000-0000-0000-0000-000000000000"}
    assert view["4 (options)"]["rk"]["value"] is True
    # Options the response did not send are shown too.
    assert view["4 (options)"]["plat"] == {"value": None, "sent": False, "meaning": "not sent; absent means: false"}
    # Labels of its own: notes where the other views have none, a key's type after its spelling.
    assert "99 (not defined in CTAP 2.2)" in view
    assert '"1" (text) (not a member: CTAP 2.2 numbers members with integer keys)' in view


def test_a_text_key_of_a_get_info_response_is_not_reported():
    codes = [finding["code"] for finding in decode_payload_text(_GET_INFO)["findings"]]

    assert "ctap-non-integer-key" not in codes


def test_the_encoder_refuses_a_get_info_view():
    decoded = decode_payload_text(_GET_INFO)["data"]

    with pytest.raises(ValueError, match="ctapDecoded.getInfoResponse is not a CTAP message the encoder builds"):
        encode_payload_text(json.dumps(decoded), "CBOR")
