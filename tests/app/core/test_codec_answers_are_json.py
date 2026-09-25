"""Every answer the codec gives is JSON, as the browser's ``response.json()`` reads it: strictly.

Python's JSON writer spells a non-finite float ``NaN``, ``Infinity`` or
``-Infinity``, which RFC 8259 has no place for, and ``response.json()`` then
throws. Each answer here is parsed with a reader that refuses them: every
decoder answer and every encoder answer it leads to, for each CBOR item the
repository holds (``tests/app/codec_corpus.py``), and for JSON input holding
NaN and Infinity.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from server.app.factory import create_app

from .. import codec_corpus
from ..conftest import TEST_SECRET_KEY


def _strict(text: str) -> Any:
    def refuse(constant: str) -> Any:
        raise AssertionError(f"{constant} in an answer: not JSON")

    return json.loads(text, parse_constant=refuse)


@pytest.fixture(scope="module")
def codec():
    client = create_app({"TESTING": True, "SECRET_KEY": TEST_SECRET_KEY}).test_client()

    def post(**body: Any) -> tuple[int, Any]:
        response = client.post("/api/codec", json=body)
        return response.status_code, _strict(response.get_data(as_text=True))

    return post


def _encoder_answers(codec, data: dict[str, Any]) -> list[int]:
    """Encode what the decoder showed every way it can be: its EDN, the whole view, its value as JSON."""

    statuses = []
    if "edn" in data:
        statuses.append(codec(payload=data["edn"], mode="encode", format="EDN")[0])
    statuses.append(codec(payload=json.dumps(data), mode="encode", format="CBOR")[0])
    if "decodedValue" in data:
        statuses.append(codec(payload=json.dumps(data["decodedValue"]), mode="encode", format="JSON")[0])
    return statuses


@pytest.mark.parametrize(("name", "item"), sorted(codec_corpus.corpus().items()), ids=lambda value: str(value)[:60])
def test_every_answer_about_an_item_in_the_repository_is_json(codec, name, item):
    for lenient in (False, True):
        status, body = codec(payload=item.hex(), lenient=lenient)
        assert status == 200, body
        assert all(code < 500 for code in _encoder_answers(codec, body["data"]))


@pytest.mark.parametrize(
    "text",
    [
        '{"a": NaN}',
        "[Infinity, -Infinity]",
        '{"credential": {"x": -Infinity}}',
        "NaN",
    ],
)
def test_every_answer_about_json_holding_nan_or_infinity_is_json(codec, text):
    for lenient in (False, True):
        status, body = codec(payload=text, lenient=lenient)
        if status == 200:
            assert all(code < 500 for code in _encoder_answers(codec, body["data"]))
    for target in ("CBOR", "JSON", "EDN"):
        status, _body = codec(payload=text, mode="encode", format=target)
        assert status in (200, 422)
