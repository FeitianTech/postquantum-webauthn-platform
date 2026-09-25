"""Decode a CTAP message, take the decoder's view of it, encode that: the same bytes, or a refusal by name.

The required property of the CTAP views (``decoder/ctap_view.py``,
``decoder/ctap_message.py``): ``ctapDecoded`` with ``data.ctap`` beside it
carries what the bytes held -- each value's type, nulls, the command or status
byte or its absence, the bytes after the message -- and the encoder rebuilds it,
never guessing. Checked through the API (``/api/codec``), with format CBOR and
with the CTAP/WebAuthn format:

- over generated messages of every kind (``tests/app/ctap_messages.py``), all in
  CTAP2 canonical form, with and without their CTAP byte and bytes after them:
  the same bytes, every time;
- over every CTAP message the repository holds (``codec_corpus.ctap_messages``),
  a map sent bare also after its own CTAP byte: the same bytes, or -- exactly
  for the messages not in CTAP2 canonical form or read past damage -- a refusal
  that says why.
"""
from __future__ import annotations

import functools
import json
from typing import Any

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from server.app.decoder import decode_payload_text
from server.app.factory import create_app

from .. import codec_corpus, ctap_messages
from ..conftest import TEST_SECRET_KEY

FORMATS = ("CBOR", "CBOR (CTAP/WebAuthn Data)")
# The findings that a message is not what the encoder writes, outside the byte strings the view keeps whole.
_CAUSES = {"canonical", "malformed", "skipped"}


@pytest.fixture(scope="module")
def codec():
    client = create_app({"TESTING": True, "SECRET_KEY": TEST_SECRET_KEY}).test_client()

    def post(**body: Any) -> tuple[int, dict]:
        response = client.post("/api/codec", json=body)
        return response.status_code, response.get_json()

    return post


def _encoded(codec, shown: dict) -> list[tuple[int, dict]]:
    return [codec(payload=json.dumps(shown), mode="encode", format=target) for target in FORMATS]


@pytest.mark.parametrize("message", list(ctap_messages.MESSAGES))
@settings(max_examples=250)
@given(data=st.data())
def test_every_generated_ctap_message_comes_back_to_its_bytes(codec, message, data):
    raw = data.draw(ctap_messages.messages(message))

    status, body = codec(payload=raw.hex())

    assert status == 200, body
    shown = body["data"]
    assert "ctapDecoded" in shown, (raw.hex(), body["type"])
    event(f"read as a {next(iter(shown['ctapDecoded']))}")
    assert "notRebuildable" not in shown["ctap"], shown["ctap"]
    for encode_status, answer in _encoded(codec, shown):
        assert encode_status == 200, answer
        assert answer["data"]["binary"]["hex"] == raw.hex()


_COMMAND = {"makeCredentialRequest": 0x01, "getAssertionRequest": 0x02}


@functools.cache
def repository_ctap_messages() -> list[tuple[str, bytes]]:
    """The repository's CTAP messages, each map sent bare also after its own CTAP byte."""

    cases = []
    for name, raw in sorted(codec_corpus.ctap_messages().items()):
        decoded = decode_payload_text(raw.hex())["data"]
        if "ctapDecoded" not in decoded:
            continue
        cases.append((name, raw))
        if decoded["ctap"]["code"] is None:
            code = _COMMAND.get(next(iter(decoded["ctapDecoded"])), 0x00)
            cases.append((f"{name}, after its CTAP byte", bytes([code]) + raw))
    return cases


def _causes(body: dict) -> list[str]:
    return [
        finding["code"]
        for finding in body["findings"]
        if finding.get("category") in _CAUSES and "<" not in str(finding.get("path"))
    ]


@pytest.mark.parametrize(("name", "raw"), repository_ctap_messages(), ids=[name[:60] for name, _raw in repository_ctap_messages()])
def test_every_ctap_message_in_the_repository_comes_back_or_is_refused_by_name(codec, name, raw):
    status, body = codec(payload=raw.hex())
    assert status == 200, body
    shown = body["data"]

    answers = _encoded(codec, shown)

    if _causes(body):
        assert "notRebuildable" in shown["ctap"]
        for encode_status, answer in answers:
            assert encode_status == 422
            assert "does not give back the bytes it was read from" in answer["error"]
    else:
        assert "notRebuildable" not in shown["ctap"], shown["ctap"]
        for encode_status, answer in answers:
            assert encode_status == 200, answer
            assert answer["data"]["binary"]["hex"] == raw.hex()


def test_the_repository_holds_ctap_messages_of_the_kinds_views_show():
    kinds = {
        next(iter(decode_payload_text(raw.hex())["data"]["ctapDecoded"]))
        for _name, raw in repository_ctap_messages()
    }

    # No makeCredential request is held as CBOR data (tests build theirs in code); the generated ones cover it.
    assert kinds == {"makeCredentialResponse", "getAssertionResponse", "getInfoResponse", "getAssertionRequest"}
    assert len(repository_ctap_messages()) >= 30
