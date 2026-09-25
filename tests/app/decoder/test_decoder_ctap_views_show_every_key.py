"""A CTAP view shows every entry of the map it reads: null members and non-integer keys too.

The makeCredential and getAssertion response views read their members by
integer key and dropped the rest -- a text key, a byte-string key, a boolean
key -- and dropped member 1 (credential) or 4 (user) when it was null, while
the decoded value, which the view replaces, was not shown at all. A key that is
not an integer is shown with its type in every makeCredential and getAssertion
view, so that neither a reader nor the encoder takes the text "fmt" for member 1;
and the encoder writes back each of them, null or not, as the view shows it.
"""
from __future__ import annotations

import json

from server.app.decoder import decode_payload_text, edn
from server.app.decoder.encode import encode_payload_text

AUTH_DATA = "00" * 32 + "01" + "00000001"
# {1: null, 2: authData, 3: h'01020304', 4: null, "note": 1}, after the SUCCESS status byte.
GET_ASSERTION_WITH_NULLS = "00" + edn.encode(f"{{1: null, 2: h'{AUTH_DATA}', 3: h'01020304', 4: null, \"note\": 1}}").hex()


def test_a_get_assertion_view_shows_null_members_and_a_text_key():
    data = decode_payload_text(GET_ASSERTION_WITH_NULLS)["data"]
    view = data["ctapDecoded"]["getAssertionResponse"]

    assert list(view) == ["1 (credential)", "2 (authData)", "3 (signature)", "4 (user)", '"note" (text)']
    assert (view["1 (credential)"], view["4 (user)"], view['"note" (text)']) == (None, None, 1)
    assert list(data["expandedJson"]) == list(view)


def test_a_make_credential_view_shows_keys_of_every_type():
    item = edn.encode(f'{{1: "none", 2: h\'{AUTH_DATA}\', 3: {{}}, "fmt": "packed", h\'05\': 5, false: 0, 99: 9}}')

    view = decode_payload_text(item.hex())["data"]["ctapDecoded"]["makeCredentialResponse"]

    assert view["1 (fmt)"] == "none"
    assert (view['"fmt" (text)'], view["h'05' (bytes)"], view["false (boolean)"], view["99"]) == ("packed", 5, 0, 9)


def test_a_request_view_shows_a_text_key_with_its_type():
    item = edn.encode('{1: "example.com", 2: h\'' + "11" * 32 + '\', "rpId": "other.example"}')

    request = decode_payload_text("02" + item.hex())["data"]["ctapDecoded"]["getAssertionRequest"]

    assert request == {"1 (rpId)": "example.com", "2 (clientDataHash)": "11" * 32, '"rpId" (text)': "other.example"}


def test_a_view_with_a_null_member_encodes_back_to_the_null_it_holds():
    # The builders read null as absent: 00 a4 01 f6 ... came back as 00 a2 ... before.
    decoded = decode_payload_text(GET_ASSERTION_WITH_NULLS)["data"]
    view = {key: value for key, value in decoded["ctapDecoded"]["getAssertionResponse"].items() if key != '"note" (text)'}

    encoded = encode_payload_text(json.dumps({"ctapDecoded": {"getAssertionResponse": view}, "ctap": {"code": 0}}), "cbor")

    assert encoded["data"]["binary"]["hex"] == "00" + edn.encode(f"{{1: null, 2: h'{AUTH_DATA}', 3: h'01020304', 4: null}}").hex()


def test_a_view_with_a_non_integer_key_encodes_back_to_its_bytes():
    decoded = decode_payload_text(GET_ASSERTION_WITH_NULLS)["data"]

    assert encode_payload_text(json.dumps(decoded), "cbor")["data"]["binary"]["hex"] == GET_ASSERTION_WITH_NULLS
    # So does its EDN.
    assert "00" + encode_payload_text(decoded["edn"], "EDN")["data"]["binary"]["hex"] == GET_ASSERTION_WITH_NULLS


def _non_integer_keys(result: dict) -> list[tuple[int, str]]:
    return [(finding["offset"], finding["path"]) for finding in result["findings"] if finding["code"] == "ctap-non-integer-key"]


def test_a_non_integer_key_in_a_ctap_map_is_a_finding_where_it_is():
    result = decode_payload_text(GET_ASSERTION_WITH_NULLS)

    note_offset = bytes.fromhex(GET_ASSERTION_WITH_NULLS).index(b"\x64note")
    assert _non_integer_keys(result) == [(note_offset, '${"note"}')]
    (finding,) = [finding for finding in result["findings"] if finding["code"] == "ctap-non-integer-key"]
    assert finding["category"] == "ctap"
    assert finding["message"].startswith('map key "note" is not an integer: CTAP 2.2 section 6 numbers the members of a getAssertion response')


def test_a_request_with_a_text_key_is_reported_too():
    item = edn.encode('{1: "example.com", 2: h\'' + "11" * 32 + '\', "rpId": "other.example", h\'01\': 0}')

    result = decode_payload_text("02" + item.hex())

    assert [path for _offset, path in _non_integer_keys(result)] == ['${"rpId"}', "${h'01'}"]


def test_a_conformant_ctap_message_and_a_plain_map_have_no_such_finding():
    from tests.app.decoder.real_vectors import (
        GET_ASSERTION_RESPONSE,
        GET_INFO,
        MAKE_CREDENTIAL_RESPONSE,
    )

    for message in (MAKE_CREDENTIAL_RESPONSE, GET_ASSERTION_RESPONSE, GET_INFO, b"\xa1\x61\x61\x01"):
        assert _non_integer_keys(decode_payload_text(message.hex())) == []
