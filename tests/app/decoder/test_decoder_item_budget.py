"""One decode reads under one item budget, over every reading of its input (``decoder/item_budget.py``).

The decoder reads an input more than once (``decode/readings.py``): each
reading it tries, and each one it checks reads the input whole too. All of them
count against one budget, so that no input multiplies its cost by being read
again; past it, the input is refused where the read that ran out was. What the
readings spell in EDN to name a part of the input counts against the same
budget, so that no input multiplies its cost by nesting a key in a key, or
repeating one.
"""
from __future__ import annotations

import base64
import time
import tracemalloc
from collections.abc import Callable

import pytest

from server.app.config.request_limits import DEFAULT_MAX_CODEC_REQUEST_BYTES
from server.app.decoder import edn, item_budget
from server.app.decoder.cbor_head import encode_head
from server.app.decoder.decode import cbor_parser
from server.app.decoder.decode.text import decode_payload_text
from tests.app import codec_corpus


def _array(count: int) -> bytes:
    """A CBOR array of ``count`` zeros: ``count + 1`` items."""

    return encode_head(4, count, None) + b"\x00" * count


def test_the_readings_of_one_input_share_one_budget():
    data = _array(4)

    # One reading reads its five items within a budget of five; the decoder's readings together do not.
    with item_budget.limit(5):
        cbor_parser.decode_item(data)
    with pytest.raises(item_budget.ItemLimitError):
        decode_payload_text(data.hex(), max_items=5)

    assert decode_payload_text(data.hex(), max_items=100)["data"]["decodedValue"] == [0, 0, 0, 0]


@pytest.mark.parametrize("lenient", [False, True])
def test_an_input_over_the_budget_is_refused_where_the_first_reading_ran_out(lenient):
    with pytest.raises(item_budget.ItemLimitError) as refused:
        decode_payload_text(_array(10).hex(), lenient=lenient, max_items=5)

    # The array, then $[0] to $[3]: the sixth item, $[4] at offset 5, is one too many.
    assert (refused.value.limit, refused.value.offset, refused.value.path) == (5, 5, "$[4]")


def test_json_over_the_budget_is_refused_rather_than_read_as_other_text():
    # The array and its three values: four.
    assert decode_payload_text("[1, 2, 3]", max_items=4)["data"]["json"] == [1, 2, 3]

    with pytest.raises(item_budget.ItemLimitError) as refused:
        decode_payload_text("[1, 2, 3]", max_items=3)
    assert (refused.value.offset, refused.value.path) == (None, "$[2]")


def _fastest_refusal_seconds(text: str) -> float:
    fastest = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        with pytest.raises(item_budget.ItemLimitError):
            decode_payload_text(text)
        fastest = min(fastest, time.perf_counter() - start)
    return fastest


def test_a_million_items_are_refused_about_as_fast_as_one_past_the_budget_and_with_little_memory():
    # Read whole, this array took 8.7 s and 465 MB.
    text = _array(1_000_000).hex()

    with pytest.raises(item_budget.ItemLimitError) as refused:
        decode_payload_text(text)

    tracemalloc.start()
    try:
        with pytest.raises(item_budget.ItemLimitError):
            decode_payload_text(text)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The first reading stops at the first item past the default: the array's head is five bytes.
    limit = item_budget.DEFAULT_MAX_ITEMS
    assert (refused.value.offset, refused.value.path) == (5 + limit - 1, f"$[{limit - 1}]")
    # Its text is still read whole, so it costs a few times what an array one item past the budget does;
    # read whole, over 700 times. Timed against each other, not a clock: the deploy gate runs ~10x slower.
    assert _fastest_refusal_seconds(text) < 20 * _fastest_refusal_seconds(_array(limit + 1).hex())
    assert peak < 30_000_000


def test_every_corpus_input_decodes_within_a_tenth_of_the_default_budget():
    # The largest reads 143 items; real inputs read at most a few thousand (docs/DECODER.md).
    for item in codec_corpus.corpus().values():
        decode_payload_text(item.hex(), max_items=item_budget.DEFAULT_MAX_ITEMS // 10)


def _key_in_key(leaf: bytes) -> bytes:
    """``leaf`` as the key of a map that is the key of a map, 60 deep: ``{{{<leaf>: 0}: 0}: 0}``."""

    return b"\xa1" * 60 + leaf + b"\x00" * 60


def _repeated_key_tower(leaf: bytes) -> bytes:
    """``{0: <what is nested>, 0: 0}`` 60 deep around ``leaf``: each level's earlier value holds every level below."""

    nested = leaf
    for _ in range(60):
        nested = b"\xa2\x00" + nested + b"\x00\x00"
    return nested


def _text(data: bytes, encoding: str) -> str:
    return data.hex() if encoding == "hex" else base64.b64encode(data).decode()


def _filling_a_request(build: Callable[[int], bytes], encoding: str) -> str:
    """``build(n)`` for the largest ``n`` whose text, in ``encoding``, a request holds, as that text."""

    room = DEFAULT_MAX_CODEC_REQUEST_BYTES - 64
    length = room // 2 if encoding == "hex" else room // 4 * 3
    text = _text(build(length - len(build(0)) - 8), encoding)
    assert len(text) <= DEFAULT_MAX_CODEC_REQUEST_BYTES
    return text


def _byte_string(length: int) -> bytes:
    return encode_head(2, length, None) + bytes(length)


def _text_string(length: int, character: bytes = b"a") -> bytes:
    return encode_head(3, length, None) + character * length


def _metered_characters(monkeypatch) -> list[int]:
    """The length of each text ``edn.spell`` writes from now on under a request's budget (``data.edn`` aside)."""

    spelled: list[int] = []
    spell = edn.spell

    def counting(node, **options):
        text = spell(node, **options)
        if item_budget.current() is not None:
            spelled.append(len(text))
        return text

    monkeypatch.setattr(edn, "spell", counting)
    return spelled


_HEX_AND_BASE64 = pytest.mark.parametrize(
    ("encoding", "lenient"), [("hex", False), ("base64", True)], ids=["hex", "base64-lenient"]
)


@_HEX_AND_BASE64
def test_a_key_repeated_deep_around_control_characters_is_refused_once_its_spelling_has_spent_the_budget(
    monkeypatch, encoding, lenient
):
    spelled = _metered_characters(monkeypatch)
    # Each level's earlier value is spelled whole before its finding cuts it short, and a control
    # character is six characters of text, each read back: 17.5 s at the request limit, spelled to the end.
    payload = _filling_a_request(lambda n: _repeated_key_tower(_text_string(n, b"\x01")), encoding)

    with pytest.raises(item_budget.SpellingLimitError) as refused:
        decode_payload_text(payload, lenient=lenient)

    assert refused.value.limit == item_budget.MAX_SPELLING_UNITS
    # A unit spells at most two characters; spelled to the end, 180 times the payload's length.
    assert sum(spelled) < 2 * item_budget.MAX_SPELLING_UNITS


@_HEX_AND_BASE64
@pytest.mark.parametrize("leaf", [_byte_string, _text_string], ids=["bytes", "text"])
def test_keys_nested_in_keys_around_a_long_string_are_refused_once_their_spelling_has_spent_the_budget(
    monkeypatch, encoding, lenient, leaf
):
    spelled = _metered_characters(monkeypatch)
    payload = _filling_a_request(lambda n: _key_in_key(leaf(n)), encoding)

    # Each level's key is spelled whole, and it holds every level below: refused, though each
    # spelling that ran out was caught and the key named otherwise.
    with pytest.raises(item_budget.SpellingLimitError):
        decode_payload_text(payload, lenient=lenient)

    # Spelled to the end, 63 (bytes) and 31 (text) times the payload's length in hex.
    assert sum(spelled) < 2 * item_budget.MAX_SPELLING_UNITS


@_HEX_AND_BASE64
def test_keys_nested_in_keys_around_many_small_items_are_refused_once_their_spelling_has_spent_the_budget(
    monkeypatch, encoding, lenient
):
    spelled = _metered_characters(monkeypatch)
    # 2,100 maps {0: 0} under 60 levels of keys: each level spells every level below it, about 82 times
    # the payload's length before the item budget ran out, which took a second.
    payload = _text(_key_in_key(encode_head(4, 2_100, None) + b"\xa1\x00\x00" * 2_100), encoding)

    with pytest.raises(item_budget.SpellingLimitError):
        decode_payload_text(payload, lenient=lenient)

    assert sum(spelled) < 2 * item_budget.MAX_SPELLING_UNITS


@_HEX_AND_BASE64
@pytest.mark.parametrize(
    "value", [_byte_string, _text_string, lambda n: _text_string(n, b"\x01")], ids=["bytes", "text", "control"]
)
def test_the_largest_flat_inputs_are_answered_and_their_edn_view_spells_nothing_against_the_budget(
    monkeypatch, encoding, lenient, value
):
    spelled = _metered_characters(monkeypatch)
    # {0: <value>} filling a request: its EDN view spells it whole once a reading, uncounted.
    payload = _filling_a_request(lambda n: b"\xa1\x00" + value(n), encoding)

    assert "edn" in decode_payload_text(payload, lenient=lenient)["data"]
    assert spelled == []


@pytest.mark.parametrize("key_head", [b"\x82", b"\xd8\x40"], ids=["array", "tag"])
def test_a_flat_map_of_600_array_or_tag_keys_is_answered(key_head):
    # [i, 0]: 0 or 64(i): 0 for i up to 600, each key spelled a few times: about a tenth of the budget.
    member = b"\x00" if key_head == b"\x82" else b""
    keys = [key_head + encode_head(0, index, None) + member for index in range(600)]
    data = encode_head(5, 600, None) + b"".join(key + b"\x00" for key in keys)

    assert len(decode_payload_text(data.hex())["data"]["decodedValue"]) == 600


@_HEX_AND_BASE64
def test_a_long_byte_string_under_a_repeated_key_is_answered(encoding, lenient):
    # The earlier value is spelled whole once for its finding: a byte a unit, far from the budget.
    payload = _filling_a_request(lambda n: b"\xa2\x00" + _byte_string(n) + b"\x00\x00", encoding)

    findings = decode_payload_text(payload, lenient=lenient)["findings"]

    [finding] = [finding for finding in findings if "earlier" in finding]

    assert finding["earlier"][0]["value"].endswith("...")
