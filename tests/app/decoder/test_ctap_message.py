"""A CTAP view's member labels, its framing, and the bytes it rebuilds (``decoder/ctap_message.py``)."""
from __future__ import annotations

import pytest

from server.app.decoder import ctap_message
from server.app.decoder.decode import cbor_parser


def _key(hex_text: str) -> dict:
    return cbor_parser.decode_item(bytes.fromhex(hex_text))[0]


def test_a_member_is_labelled_by_its_number_and_name():
    assert ctap_message.member_label("makeCredentialResponse", _key("01")) == "1 (fmt)"
    assert ctap_message.member_label("getInfoResponse", _key("03")) == "3 (aaguid)"
    assert ctap_message.member_label("makeCredentialResponse", _key("1863")) == "99"
    # Text always with its type: a CTAP message numbers its members.
    assert ctap_message.member_label("makeCredentialResponse", _key("63666d74")) == '"fmt" (text)'
    assert ctap_message.member_label("makeCredentialResponse", _key("6131")) == '"1" (text)'


@pytest.mark.parametrize(
    ("label", "key"),
    [("1 (fmt)", 1), ("1", 1), ("99", 99), ('"fmt" (text)', "fmt"), ("h'01' (bytes)", b"\x01")],
)
def test_a_member_label_names_its_key(label, key):
    assert ctap_message.read_member_key("makeCredentialResponse", label) == key


@pytest.mark.parametrize(
    ("label", "message"),
    [
        ("1 (rpId)", r'the label "1 \(rpId\)" names rpId, but member 1 of a makeCredentialResponse is fmt'),
        ("99 (x)", "member 99 of a makeCredentialResponse is not defined in CTAP 2.2"),
        ("fmt", r'"fmt" names no member: a makeCredentialResponse numbers its members, as "1 \(fmt\)"'),
    ],
)
def test_a_label_that_names_no_member_is_refused(label, message):
    with pytest.raises(ValueError, match=message):
        ctap_message.read_member_key("makeCredentialResponse", label)


def test_a_view_rebuilds_its_framing_members_and_trailing_bytes():
    view = {"1 (fmt)": "none", "2 (authData)": {"raw": "aa" * 37, "trailingBytesHex": "bb", "signCount": 5}, "3 (attStmt)": {}}

    rebuilt = ctap_message.rebuild("makeCredentialResponse", view, {"code": 0, "trailingBytesHex": "0000"})

    assert rebuilt == bytes.fromhex("00" "a3" "01646e6f6e65" "025826" + "aa" * 37 + "bb" "03a0" "0000")
    assert ctap_message.rebuild("makeCredentialResponse", view, {"code": None})[:1] == b"\xa3"


def test_an_attestation_certificate_is_rebuilt_from_its_raw_bytes():
    view = {"1 (fmt)": "packed", "2 (authData)": {"raw": "aa" * 37}, "3 (attStmt)": {"x5c": [{"raw": "3001", "pem": "x"}, "02"]}}

    rebuilt = ctap_message.rebuild("makeCredentialResponse", view, {"code": None})

    assert rebuilt.endswith(bytes.fromhex("03a1" "6378356382" "423001" "4102"))


@pytest.mark.parametrize(
    ("view", "framing", "message"),
    [
        ({"1": 1, "1 (fmt)": 2}, {"code": None}, "member 1 is given twice"),
        ({"1": 1}, {"code": 256}, "ctap.code must be a byte"),
        ({"1": 1}, {"code": "0x00"}, "ctap.code must be a byte"),
        ({"1": 1}, {"code": None, "trailingBytesHex": "zz"}, "ctap.trailingBytesHex must be hex"),
        ({"2 (authData)": {"raw": "zz"}}, {"code": None}, r"\.raw must be hex"),
    ],
)
def test_a_view_that_does_not_rebuild_is_refused(view, framing, message):
    with pytest.raises(ValueError, match=message):
        ctap_message.rebuild("makeCredentialResponse", view, framing)


def test_a_message_the_views_do_not_name_is_refused():
    with pytest.raises(ValueError, match="clientPinResponse is not a CTAP message this view names"):
        ctap_message.rebuild("clientPinResponse", {}, {"code": None})
