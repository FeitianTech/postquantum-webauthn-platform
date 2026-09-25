"""A CTAP view shows every entry of the map it reads: null members and non-integer keys too.

The makeCredential and getAssertion response views read their members by
integer key and dropped the rest -- a text key, a byte-string key, a boolean
key -- and dropped member 1 (credential) or 4 (user) when it was null, while
the decoded value, which the view replaces, was not shown at all. A key that is
not an integer is shown with its type in every makeCredential and getAssertion
view, so that neither a reader nor the encoder takes the text "fmt" for member 1.
"""
from __future__ import annotations

import json

import pytest

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


def test_a_view_with_a_null_member_is_refused_by_the_encoder_not_encoded_without_it():
    # The builders read null as absent: 00 a4 01 f6 ... came back as 00 a2 ... before.
    decoded = decode_payload_text(GET_ASSERTION_WITH_NULLS)["data"]
    view = {key: value for key, value in decoded["ctapDecoded"]["getAssertionResponse"].items() if key != '"note" (text)'}

    with pytest.raises(ValueError, match=r"getAssertionResponse member 1 \(credential\) is null"):
        encode_payload_text(json.dumps({"ctapDecoded": {"getAssertionResponse": view}, "ctap": decoded["ctap"]}), "cbor")


def test_a_view_with_a_non_integer_key_is_refused_by_the_encoder():
    decoded = decode_payload_text(GET_ASSERTION_WITH_NULLS)["data"]

    with pytest.raises(ValueError, match=r"""key '"note" \(text\)' is a text key, not a CTAP member"""):
        encode_payload_text(json.dumps(decoded), "cbor")
    # Its EDN rebuilds it exactly.
    assert "00" + encode_payload_text(decoded["edn"], "EDN")["data"]["binary"]["hex"] == GET_ASSERTION_WITH_NULLS
