"""A getInfo response as the decoder shows it (``ctapDecoded.getInfoResponse``), and as the encoder reads it back."""
from __future__ import annotations

import json

from server.app.decoder import decode_payload_text, edn, encode_payload_text

# SUCCESS, then {1: ["FIDO_2_0"], 3: aaguid, 4: {"rk": true}, 99: 2, "1": 1}.
_GET_INFO = "00" + edn.encode('{1: ["FIDO_2_0"], 3: h\'' + "00" * 16 + '\', 4: {"rk": true}, 99: 2, "1": 1}').hex()


def test_the_view_shows_every_member_as_sent_and_what_they_mean_beside_it():
    data = decode_payload_text(_GET_INFO)["data"]
    view = data["ctapDecoded"]["getInfoResponse"]

    # As sent, labelled as every CTAP view labels a member.
    assert view == {"1 (versions)": ["FIDO_2_0"], "3 (aaguid)": "00" * 16, "4 (options)": {"rk": True}, "99": 2, '"1" (text)': 1}
    # What they mean, beside: the options not sent too, and each note.
    meaning = data["getInfoDecoded"]
    assert meaning["3 (aaguid)"] == {"hex": "00" * 16, "guid": "00000000-0000-0000-0000-000000000000"}
    assert meaning["4 (options)"]["plat"] == {"value": None, "sent": False, "meaning": "not sent; absent means: false"}
    assert meaning["99"] == {"value": 2, "note": "not a member CTAP 2.2 section 6.4 defines"}
    assert meaning['"1" (text)']["note"] == "not a member: CTAP 2.2 numbers members with integer keys"


def test_a_text_key_of_a_get_info_response_is_reported():
    findings = decode_payload_text(_GET_INFO)["findings"]

    assert [finding["path"] for finding in findings if finding["code"] == "ctap-non-integer-key"] == ['${"1"}']


def test_the_encoder_rebuilds_a_get_info_view():
    decoded = decode_payload_text(_GET_INFO)["data"]

    assert encode_payload_text(json.dumps(decoded), "CBOR")["data"]["binary"]["hex"] == _GET_INFO
