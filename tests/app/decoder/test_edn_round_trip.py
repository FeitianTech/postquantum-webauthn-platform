"""Decode, spell as EDN, encode: the same bytes, for every item the strict parser accepts.

The required property of the EDN view: the text describes the item exactly, so
the encoder's EDN input rebuilds it byte for byte -- non-canonical heads,
indefinite lengths chunk by chunk, duplicate map keys, tags inside tags, float
widths and NaN payloads included. Checked over generated items
(``tests/app/cbor_items.py``) and over every item the repository's tests and
golden records hold (``tests/app/codec_corpus.py``).
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings

from server.app.decoder import edn
from server.app.decoder.decode.cbor_parser import decode_item

from .. import cbor_items, codec_corpus


def _round_trip(data: bytes) -> None:
    node, end, skipped = decode_item(data)
    assert end == len(data) and not skipped
    for inline in (False, True):
        text = edn.spell(node, inline=inline)
        assert edn.encode(text) == data, text


@settings(max_examples=3000)
@given(cbor_items.items)
def test_every_generated_item_round_trips_through_its_edn(data):
    _round_trip(data)


@pytest.mark.parametrize(("name", "data"), sorted(codec_corpus.corpus().items()), ids=lambda value: str(value)[:60])
def test_every_item_in_the_repository_round_trips_through_its_edn(name, data):
    _round_trip(data)
