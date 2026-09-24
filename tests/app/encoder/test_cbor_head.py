"""decoder/cbor_head writes every CBOR head: the shortest, or the width asked for."""
from __future__ import annotations

import pytest

from server.app.decoder.cbor_head import encode_head, shortest_info


@pytest.mark.parametrize(
    ("argument", "expected"),
    [(0, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"), (65535, "19ffff"),
     (65536, "1a00010000"), (2**32 - 1, "1affffffff"), (2**32, "1b0000000100000000"), (2**64 - 1, "1bffffffffffffffff")],
)
def test_the_shortest_head_holds_the_argument(argument, expected):
    assert encode_head(0, argument).hex() == expected


@pytest.mark.parametrize(
    ("major_type", "argument", "info", "expected"),
    [(0, 5, 24, "1805"), (0, 5, 25, "190005"), (0, 5, 26, "1a00000005"), (0, 5, 27, "1b0000000000000005"),
     (2, 1, 25, "590001"), (4, 2, 24, "9802"), (6, 1, 25, "d90001"), (1, 0, 0, "20"), (3, 7, 7, "67")],
)
def test_a_head_is_written_at_the_width_asked_for(major_type, argument, info, expected):
    assert encode_head(major_type, argument, info).hex() == expected


def test_an_indefinite_length_head_has_no_argument():
    assert [encode_head(major, None, 31).hex() for major in (2, 3, 4, 5)] == ["5f", "7f", "9f", "bf"]
    with pytest.raises(ValueError, match="no argument"):
        encode_head(4, 1, 31)


@pytest.mark.parametrize(
    ("major_type", "argument", "info", "message"),
    [(0, 256, 24, "does not fit"), (0, 24, 23, "is the argument itself"), (0, 1, 28, "reserved"),
     (0, -1, None, "non-negative"), (0, 2**64, None, "64-bit"), (8, 0, None, "major types")],
)
def test_a_head_that_cannot_be_written_is_refused(major_type, argument, info, message):
    with pytest.raises(ValueError, match=message):
        encode_head(major_type, argument, info)


def test_shortest_info_names_each_width():
    assert [shortest_info(value) for value in (0, 23, 24, 256, 65536, 2**32)] == [0, 23, 24, 25, 26, 27]
