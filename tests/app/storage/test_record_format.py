"""``storage.record_format``: the JSON a credential record is stored as."""
from __future__ import annotations

import pytest

from server.app.storage import record_format


@pytest.mark.parametrize("value", [(1, 2), {1, 2}, frozenset(), object()], ids=["tuple", "set", "frozenset", "object"])
def test_a_record_holding_a_value_the_format_cannot_write_is_refused(value):
    with pytest.raises(TypeError, match="which the store does not write"):
        record_format.encode_records([{"value": value}])


def test_a_record_reads_back_as_it_was_written():
    record = {"id": b"\x01\x02", "count": 3, "ratio": 0.5, "flag": True, "none": None, "cose": {1: 2, -1: b"k"}, "list": ["a", b"b"]}

    assert record_format.decode_payload(record_format.encode_records([record])) == [record]
