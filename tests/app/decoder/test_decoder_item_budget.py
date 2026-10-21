"""One decode reads under one item budget, over every reading of its input (``decoder/item_budget.py``).

The decoder reads an input more than once (``decode/readings.py``): each
reading it tries, and each one it checks reads the input whole too. All of them
count against one budget, so that no input multiplies its cost by being read
again; past it, the input is refused where the read that ran out was.
"""
from __future__ import annotations

import time
import tracemalloc

import pytest

from server.app.decoder import item_budget
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


def test_a_million_items_are_refused_in_well_under_a_second_and_with_little_memory():
    # Read whole, this array took 8.7 s and 465 MB.
    text = _array(1_000_000).hex()

    start = time.perf_counter()
    with pytest.raises(item_budget.ItemLimitError) as refused:
        decode_payload_text(text)
    elapsed = time.perf_counter() - start

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
    assert elapsed < 1
    assert peak < 30_000_000


def test_every_corpus_input_decodes_within_a_tenth_of_the_default_budget():
    # The largest reads 143 items; real inputs read at most a few thousand (docs/DECODER.md).
    for item in codec_corpus.corpus().values():
        decode_payload_text(item.hex(), max_items=item_budget.DEFAULT_MAX_ITEMS // 10)
