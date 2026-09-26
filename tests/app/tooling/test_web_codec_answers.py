"""The server answers web/'s Codec tests render are the server's own, and stay so.

``web/src/test/codec-answers.json`` holds what ``POST /api/codec`` answers for a
few inputs, each with its request and status; the React component tests render
those answers rather than hand-written ones. This asks the app again and fails
when an answer has changed. ``CODEC_ANSWERS_WRITE=1`` rewrites the file (review
the diff, as for the characterization goldens).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from tests.app.decoder.real_vectors import (
    GET_INFO,
    MAKE_CREDENTIAL_RESPONSE,
    PACKED_ATT_STMT,
)

_ANSWERS = Path(__file__).resolve().parents[3] / "web" / "src" / "test" / "codec-answers.json"


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return "\n".join(["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----"])


def _decode(payload: str, **extra) -> dict:
    return {"payload": payload, "mode": "decode", **extra}


def _encode(payload: object, fmt: str) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"payload": text, "mode": "encode", "format": fmt}


REQUESTS = {
    # {1: "a", "1": "b", 1: "c"}: a key repeated, and two keys that read alike as JSON.
    "decode-duplicate-and-colliding-keys": _decode("a301616161316162016163"),
    "decode-nan-strict": _decode('{"a": NaN}'),
    "decode-nan-lenient": _decode('{"a": NaN}', lenient=True),
    "decode-cbor-not-well-formed-lenient": _decode("a2010203", lenient=True),
    "decode-get-info-framed": _decode("00" + GET_INFO.hex()),
    "decode-make-credential-padded": _decode("00" + MAKE_CREDENTIAL_RESPONSE.hex() + "0000000000"),
    "decode-certificate": _decode(_pem(PACKED_ATT_STMT["x5c"][0])),
    "encode-cbor": _encode({"a": 1}, "CBOR (canonical)"),
    "encode-edn": _encode('{1: "a", "1": "b", 1: "c"}', "EDN"),
    "encode-ctap": _encode({"01": "example.com", "02": "22" * 32}, "CBOR (CTAP/WebAuthn Data)"),
    "encode-json": _encode({"a": 1}, "JSON (binary)"),
    "encode-der": _encode({"binary": {"base64url": "AQIDBAU"}}, "DER"),
    "encode-pem": _encode({"hex": "0102030405"}, "PEM"),
    "encode-cose": _encode({"1": 2, "3": -7, "-1": 1, "-2": bytes(range(32)).hex(), "-3": bytes(range(32, 64)).hex()}, "COSE"),
}


def _answers(client) -> dict:
    answers = {}
    for name, body in REQUESTS.items():
        response = client.post("/api/codec", json=body)
        answers[name] = {"request": body, "status": response.status_code, "answer": response.get_json()}
    return answers


def test_the_codec_answers_web_renders_are_the_servers(client):
    answers = _answers(client)
    if os.environ.get("CODEC_ANSWERS_WRITE") == "1":
        _ANSWERS.write_text(json.dumps(answers, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    assert json.loads(_ANSWERS.read_text(encoding="utf-8")) == answers


def test_every_answer_is_what_its_test_needs():
    answers = json.loads(_ANSWERS.read_text(encoding="utf-8"))
    assert {name: entry["status"] for name, entry in answers.items()} == {
        name: 422 if name == "decode-nan-strict" else 200 for name in REQUESTS
    }
    categories = {finding["category"] for finding in answers["decode-duplicate-and-colliding-keys"]["answer"]["findings"]}
    assert categories == {"rendering", "canonical"}
    assert answers["decode-nan-strict"]["answer"]["offset"] == 6
