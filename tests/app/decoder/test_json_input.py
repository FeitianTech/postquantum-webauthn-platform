"""``decoder.decode.json_input``: JSON the decoder is given, read value by value."""
from __future__ import annotations

import pytest

from server.app.decoder import item_budget
from server.app.decoder.decode import json_input


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
