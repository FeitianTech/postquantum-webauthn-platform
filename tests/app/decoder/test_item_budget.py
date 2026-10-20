"""``decoder.item_budget``: one count of the items a request reads, and its refusal."""
from __future__ import annotations

import contextlib

import pytest

from server.app.decoder import item_budget


def test_items_are_counted_to_the_limit_and_the_next_is_refused_where_it_was_read():
    with pytest.raises(item_budget.ItemLimitError) as refused:
        with item_budget.limit(2) as budget:
            budget.charge(0, "$")
            budget.charge(1, "$[0]")
            assert budget.used == 2
            budget.charge(2, "$[1]")

    assert isinstance(refused.value, ValueError)
    assert (refused.value.limit, refused.value.offset, refused.value.path) == (2, 2, "$[1]")


def test_a_refusal_caught_inside_the_block_is_raised_again_when_the_block_ends():
    with pytest.raises(item_budget.ItemLimitError) as refused:
        with item_budget.limit(0) as budget:
            # A reading whose parse fails is "not this reading": the decoder goes on.
            with contextlib.suppress(ValueError):
                budget.charge(5, "$[3]")

    assert (refused.value.offset, refused.value.path) == (5, "$[3]")


def test_the_first_refusal_is_raised_whatever_error_ends_the_block():
    with pytest.raises(item_budget.ItemLimitError) as refused:
        with item_budget.limit(0) as budget:
            with contextlib.suppress(ValueError):
                budget.charge(5, "$[3]")
            # Every later read is refused at once, and a reading may then fail otherwise.
            with contextlib.suppress(ValueError):
                budget.charge(0, "$")
            raise KeyError("what the read that ran out would have given")

    assert (refused.value.offset, refused.value.path) == (5, "$[3]")


def test_an_error_in_a_block_within_its_budget_is_raised_as_it_is():
    with pytest.raises(KeyError):
        with item_budget.limit(1) as budget:
            budget.charge(0, "$")
            raise KeyError("not the budget's")


def test_nothing_counts_outside_a_limit_or_inside_unmetered():
    assert item_budget.current() is None
    with item_budget.limit(1) as budget:
        assert item_budget.current() is budget
        with item_budget.unmetered():
            assert item_budget.current() is None
        assert item_budget.current() is budget
    assert item_budget.current() is None


@pytest.mark.parametrize(
    ("offset", "path", "where"),
    [(20004, "$[19999]", "offset 20004 ($[19999])"), (None, "$[2]", "$[2]"), (7, None, "offset 7")],
)
def test_the_refusal_names_the_limit_and_where_its_read_was(offset, path, where):
    assert str(item_budget.ItemLimitError(20000, offset, path)) == (
        f"Too many items at {where}: the codec reads at most 20000 items (CBOR items, JSON values, EDN items) "
        "for one request, over all its readings of the input"
    )
