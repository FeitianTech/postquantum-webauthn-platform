"""``decoder.decode.json_input``: JSON the decoder is given, read value by value."""
from __future__ import annotations

import json
import tracemalloc

import pytest

from server.app.decoder import item_budget
from server.app.decoder.decode import json_input, readings


def _nested(depth: int) -> str:
    """A 1 inside ``depth`` arrays, one in the next: the 1 is ``depth`` deep."""

    return "[" * depth + "1" + "]" * depth


def test_json_of_as_many_values_as_the_budget_is_read_and_one_more_is_refused_at_its_path():
    # The array, 1, the object, its member's array and 2: five values.
    text = '[1, {"a": [2]}]'

    with item_budget.limit(5) as budget:
        value, findings = json_input.read(text)
    assert (value, findings, budget.used) == ([1, {"a": [2]}], [], 5)

    with pytest.raises(item_budget.ItemLimitError) as refused, item_budget.limit(4):
        json_input.read(text)
    # The JSON reader gives no positions: a path, and no offset.
    assert (refused.value.offset, refused.value.path) == (None, '$[1]{"a"}[0]')


def test_json_read_leniently_is_refused_at_the_budget_as_strict_json_is():
    with pytest.raises(item_budget.ItemLimitError) as refused, item_budget.limit(2):
        json_input.read("[NaN, 1]", lenient=True)
    assert (refused.value.offset, refused.value.path) == (None, "$[1]")


def test_json_nested_64_deep_is_read_and_a_value_one_deeper_is_refused_where_it_starts():
    assert json_input.read(_nested(64)) == (json.loads(_nested(64)), [])

    with pytest.raises(json_input.JsonDepthError) as refused:
        json_input.read(_nested(65))
    path = "$" + "[0]" * 65
    assert (refused.value.offset, refused.value.path) == (65, path)
    assert str(refused.value) == (
        f"JSON nested too deep at offset 65 ({path}): values are nested more than 64 deep, the most the decoder reads"
    )


@pytest.mark.parametrize("lenient", [False, True])
def test_a_value_too_deep_in_objects_is_named_by_their_keys_strict_or_lenient(lenient):
    # Each level is the 11 characters {"\u00e9": , its key spelled as the path spells it.
    with pytest.raises(json_input.JsonDepthError) as refused:
        json_input.read('{"\\u00e9": ' * 65 + "1" + "}" * 65, lenient=lenient)
    assert (refused.value.offset, refused.value.path) == (11 * 65, "$" + '{"é"}' * 65)


def test_json_nested_deeper_than_python_reads_is_refused_at_the_first_value_too_deep():
    # json.loads runs out of stack long before 100,000 levels.
    with pytest.raises(json_input.JsonDepthError) as refused:
        json_input.read("[" * 100_000 + "]" * 100_000)
    assert (refused.value.offset, refused.value.path) == (65, "$" + "[0]" * 65)


def test_a_long_string_before_the_value_too_deep_is_stepped_over_in_memory_about_its_own_size():
    # A million characters: state kept for each one took about 118 MB.
    text = '["' + "a" * 1_000_000 + '", ' + _nested(64) + "]"

    tracemalloc.start()
    try:
        with pytest.raises(json_input.JsonDepthError) as refused:
            json_input.read(text)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert (refused.value.offset, refused.value.path) == (1_000_005 + 64, "$[1]" + "[0]" * 64)
    assert peak < 4 * len(text)


def test_the_offset_in_json_bytes_too_deep_counts_bytes():
    text = '["é", true, ' + _nested(64) + "]"

    with pytest.raises(json_input.JsonDepthError) as refused:
        json_input.read_bytes(text.encode("utf-8"))
    # Twelve characters, thirteen bytes, before the 64 arrays.
    assert (refused.value.offset, refused.value.path) == (13 + 64, "$[2]" + "[0]" * 64)


def test_json_too_deep_is_refused_rather_than_taken_for_text_that_is_no_json():
    with pytest.raises(json_input.JsonDepthError):
        json_input.read_or_none(_nested(65))

    assert readings.JSON_TEXT in readings.reads_whole(_nested(64).encode())
    assert readings.JSON_TEXT not in readings.reads_whole(_nested(65).encode())


def test_a_recursion_error_its_depth_does_not_explain_is_raised_as_it_is(monkeypatch):
    def run_out(*_args, **_kwargs):
        raise RecursionError("the stack ran out before the reader started")

    monkeypatch.setattr(json, "loads", run_out)

    with pytest.raises(RecursionError):
        json_input.read("[1]")
