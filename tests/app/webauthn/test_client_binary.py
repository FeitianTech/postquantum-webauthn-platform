"""``webauthn.client_binary``: bytes a client sends, as bytes or strict text."""

from __future__ import annotations

import base64

import pytest

from server.app import encoding
from server.app.webauthn import client_binary
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.security.ceremony_helpers import b64u

STANDARD = base64.b64encode(b"\xfb\xef\xbe").decode("ascii")  # "++++"-style, base64 only
URLSAFE = base64.urlsafe_b64encode(b"\xfb\xef\xbe").decode("ascii")  # "----"-style, base64url only


@pytest.mark.parametrize("value", [b"\x00\x01", bytearray(b"\x00\x01"), memoryview(b"\x00\x01")])
def test_base64url_bytes_are_returned_as_they_are(value):
    assert client_binary.decode_base64url_bytes(value) == b"\x00\x01"


@pytest.mark.parametrize("value", ["   ", "abc*", "br*ken", 12345, object(), None])
def test_what_is_not_base64url_is_empty(value):
    # Outside the alphabet is absent, not decoded down to the characters that survive.
    assert client_binary.decode_base64url_bytes(value) == b""


def test_an_assertion_credential_id_is_its_raw_id_or_its_id():
    assert client_binary.extract_assertion_credential_id({"rawId": b"\x10\x11"}) == b"\x10\x11"
    assert client_binary.extract_assertion_credential_id({"id": "EBE"}) == b"\x10\x11"


@pytest.mark.parametrize("response", [{"rawId": "abc*"}, {"id": 12345}, {}, ["rawId"], None])
def test_an_assertion_without_a_readable_credential_id_has_none(response):
    assert client_binary.extract_assertion_credential_id(response) is None


def test_binary_text_that_is_blank_is_refused():
    with pytest.raises(encoding.EncodingError, match="empty binary value"):
        client_binary.decode_binary_text("   ")


@pytest.mark.parametrize(
    ("wrapped", "expected"),
    [
        ({"base64": STANDARD}, b"\xfb\xef\xbe"),
        ({"base64url": URLSAFE}, b"\xfb\xef\xbe"),
        ({"base64url": "YWI"}, b"ab"),
        # A wrapper around another wrapper, or around bytes, reads what it holds.
        ({"hex": {"$hex": "6162"}}, b"ab"),
        ({"base64url": {"$hex": "6162"}}, b"ab"),
        ({"base64": {"$hex": "6162"}}, b"ab"),
        ({"$hex": b"ab"}, b"ab"),
    ],
)
def test_a_wrapper_with_or_without_its_dollar_reads_its_own_alphabet(wrapped, expected):
    assert client_binary.read(wrapped, wrappers=True) == expected


@pytest.mark.parametrize(
    ("wrapped", "error"),
    [
        ({"hex": "  "}, "empty binary value"),
        ({"base64": "   "}, "empty binary value"),
        ({"base64url": "   "}, "empty binary value"),
        # Each decodes only its own alphabet: a mismatch used to come back as other bytes.
        ({"base64url": STANDARD}, "invalid binary value"),
        ({"base64": URLSAFE}, "invalid binary value"),
    ],
)
def test_a_wrapper_holding_nothing_or_another_alphabet_is_refused(wrapped, error):
    with pytest.raises(ValueError, match=error):
        client_binary.read(wrapped, wrappers=True)


def test_a_mapping_without_a_wrapper_is_not_binary():
    with pytest.raises(ValueError, match="unsupported binary value type"):
        client_binary.read({"other": "6162"}, wrappers=True)


def test_byte_values_are_read_only_where_a_caller_takes_them():
    assert client_binary.read([97, 98], iterables=True) == b"ab"

    with pytest.raises(ValueError, match="unsupported binary value type"):
        client_binary.read([97, 98])


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"$hex": "6162"}, b"ab"),
        ({"$base64": "YWI="}, b"ab"),
        ({"$base64url": "YWI"}, b"ab"),
        ("6162", "6162"),
        # Anything else, including a wrapper around something other than text, as given.
        ({"$base64": 5}, {"$base64": 5}),
        ({"$base64url": 5}, {"$base64url": 5}),
        ({"other": "6162"}, {"other": "6162"}),
        (7, 7),
    ],
)
def test_an_advanced_request_value_is_unwrapped_and_anything_else_given_back(value, expected):
    assert client_binary.unwrap_request_value(value) == expected


def test_a_bare_request_field_is_read_as_hex():
    assert client_binary.read_request_field("6162") == b"ab"
    assert client_binary.read_request_field({"$base64url": "YWI"}) == b"ab"


def test_decode_client_binary_accepts_base64url_mapping_key():
    raw = b"\x00\x01\x02\xfa"
    decoded = client_binary.read({"$base64url": b64u(raw)}, wrappers=True)

    assert decoded == raw


def test_decode_client_binary_honors_explicit_hex_wrapper():
    decoded = client_binary.read({"$hex": "0011223344556677"}, wrappers=True)

    assert decoded == bytes.fromhex("0011223344556677")


def test_decode_client_binary_rejects_invalid_explicit_hex_wrapper():
    with pytest.raises(ValueError, match="invalid binary value"):
        client_binary.read({"$hex": "zz"}, wrappers=True)


def test_decode_client_binary_rejects_invalid_explicit_base64url_wrapper():
    with pytest.raises(ValueError, match="invalid binary value"):
        client_binary.read({"$base64url": "%%%"}, wrappers=True)


def test_decode_client_binary_rejects_invalid_string_value():
    with pytest.raises(ValueError, match="invalid binary value"):
        client_binary.read("g$", wrappers=True)


def test_decode_client_binary_rejects_unsupported_input_type():
    with pytest.raises(ValueError, match="unsupported binary value type"):
        client_binary.read(1234, wrappers=True)


def test_decode_client_binary_handles_none_bytes_and_empty_string_inputs():
    with pytest.raises(ValueError, match="missing binary value"):
        client_binary.read(None, wrappers=True)

    assert client_binary.read(b"\x00\x01\x02", wrappers=True) == b"\x00\x01\x02"

    with pytest.raises(ValueError, match="empty binary value"):
        client_binary.read("   ", wrappers=True)


def test_advanced_client_binary_rejects_plain_text():
    with pytest.raises(ValueError):
        client_binary.read(PLAIN_TEXT, wrappers=True)


def test_simple_binary_value_rejects_plain_text():
    with pytest.raises(ValueError):
        client_binary.read(PLAIN_TEXT, iterables=True)


def test_base64url_helpers_do_not_return_garbage_for_plain_text():
    """The credential-ID intake path must return nothing, not junk bytes."""

    assert client_binary.decode_base64url_bytes(PLAIN_TEXT) == b""
    assert client_binary.extract_assertion_credential_id({"rawId": PLAIN_TEXT}) is None


def test_credential_intake_reads_both_base64_alphabets_exactly():
    raw = b"\xfb\xef\xbe\xff\xee\xdd"
    standard = base64.b64encode(raw).decode("ascii").rstrip("=")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard or "/" in standard
    assert "-" in urlsafe or "_" in urlsafe

    assert client_binary.read(standard, wrappers=True) == raw
    assert client_binary.read(urlsafe, wrappers=True) == raw
    assert client_binary.read(standard, iterables=True) == raw
    assert client_binary.read(urlsafe, iterables=True) == raw


def test_decode_binary_value_decodes_base64url_string():
    raw = b"\x00\x01\xfe\xff"

    assert client_binary.read(b64u(raw), iterables=True) == raw


def test_decode_binary_value_decodes_standard_base64_string():
    raw = b"\xfb\xef\xff"
    encoded = base64.b64encode(raw).decode("ascii")

    assert client_binary.read(encoded, iterables=True) == raw


def test_decode_binary_value_falls_back_to_hex_when_base64_decoders_fail():
    # Separated or spaced hex cannot be base64, so it reaches the hex reading.
    assert client_binary.read("41 42 43", iterables=True) == b"ABC"
    assert client_binary.read("41:42:43", iterables=True) == b"ABC"

    # An unbroken run of hex digits can be valid base64 as well, and base64
    # still wins where it is: the precedence predates the strictness work and
    # is left alone so stored credential IDs keep decoding to the same bytes.
    assert client_binary.read("0000", iterables=True) == base64.b64decode("0000")

    # "414243" is not canonical base64 -- its final quantum carries bits that
    # re-encode to something else -- so it is no longer accepted as base64 and
    # falls through to the hex reading it plainly is.
    assert client_binary.read("414243", iterables=True) == b"ABC"


def test_decode_binary_value_decodes_iterable_of_ints():
    assert client_binary.read([65, 66, 67], iterables=True) == b"ABC"


@pytest.mark.parametrize(
    "value,pattern",
    [
        (None, "missing binary value"),
        ("   ", "empty binary value"),
        ("g$", "invalid binary value"),
        (1234, "unsupported binary value type"),
        (["A"], "invalid iterable value"),
    ],
)
def test_decode_binary_value_rejects_invalid_inputs(value, pattern):
    with pytest.raises(ValueError, match=pattern):
        client_binary.read(value, iterables=True)
