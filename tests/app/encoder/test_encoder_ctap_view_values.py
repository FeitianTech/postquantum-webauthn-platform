"""The values inside a CTAP view, decoded and encoded back: what the round trip keeps of what the bytes held.

Each message is canonical, so its view could give back exactly its bytes.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from server.app.decoder.cbor_canonical import _canonical_cbor_dumps
from server.app.decoder.decode.cbor_parser import CborDiagnostic

_AUTH_DATA = hashlib.sha256(b"example.com").digest() + b"\x01" + bytes(4)
_HASH = b"\x11" * 32
_PARAMS = [{"alg": -7, "type": "public-key"}]


def _message(code: int, members: dict) -> bytes:
    return bytes([code]) + _canonical_cbor_dumps(members)


def _round_trip(message: bytes) -> bytes:
    decoded = decode_payload_text(message.hex())["data"]
    return bytes.fromhex(encode_payload_text(json.dumps(decoded), "CBOR")["data"]["binary"]["hex"])


CHANGED = [
    # SafetyNet's ver, the text "14574037", comes back as the bytes 14 57 40 37.
    ("SafetyNet ver", _message(0, {1: "android-safetynet", 2: _AUTH_DATA, 3: {"ver": "14574037", "response": b"x.y.z"}})),
    # A null user icon is dropped.
    ("null user icon", _message(1, {1: _HASH, 2: {"id": "example.com"}, 3: {"id": b"u", "icon": None}, 4: _PARAMS})),
    # hmac-secret's integer keys come back as text.
    ("nested integer keys", _message(2, {1: "example.com", 2: _HASH, 4: {"hmac-secret": {1: {1: 2}, 2: _HASH}}})),
    # A byte string inside an extension comes back as text.
    ("bytes in an extension", _message(2, {1: "example.com", 2: _HASH, 4: {"x": b"\xab\xcd"}})),
    # A tag comes back as a map {"tag": 2, "value": "01"}.
    ("tag in an extension", _message(2, {1: "example.com", 2: _HASH, 4: {"x": CborDiagnostic("2(h'01')", "tag")}})),
    # An x5c entry that is no byte string is dropped; an x5c that is no array comes back empty.
    ("x5c entry not bytes", _message(0, {1: "packed", 2: _AUTH_DATA, 3: {"alg": -7, "sig": b"s", "x5c": [1, b"\x01"]}})),
    ("x5c not an array", _message(0, {1: "packed", 2: _AUTH_DATA, 3: {"alg": -7, "sig": b"s", "x5c": b"\x01"}})),
]

REFUSED = [
    # A user name sent as bytes is shown as {"text", "binary"}, which the encoder refuses.
    (
        "user name bytes",
        _message(1, {1: _HASH, 2: {"id": "example.com"}, 3: {"id": b"u", "name": b"alice"}, 4: _PARAMS}),
        "user.name must be a non-empty string",
    ),
    # A compound statement, an array, is refused as not bytes.
    (
        "compound statement",
        _message(0, {1: "compound", 2: _AUTH_DATA, 3: [{"fmt": "none", "attStmt": {}}]}),
        "Unable to interpret attStmt as binary data",
    ),
]


@pytest.mark.parametrize(("name", "message"), CHANGED, ids=[name for name, _ in CHANGED])
def test_a_view_encodes_back_to_other_bytes(name, message):
    assert _round_trip(message) != message


@pytest.mark.parametrize(("name", "message", "refusal"), REFUSED, ids=[name for name, _m, _r in REFUSED])
def test_a_view_is_refused(name, message, refusal):
    with pytest.raises(ValueError, match=refusal):
        _round_trip(message)


def test_expanded_json_wraps_an_attestation_statement_that_is_not_a_map():
    as_bytes = decode_payload_text(_message(0, {1: "packed", 2: _AUTH_DATA, 3: b"\x01\x02"}).hex())["data"]
    as_array = decode_payload_text(REFUSED[1][1].hex())["data"]

    assert as_bytes["expandedJson"]["3 (attStmt)"] == {"sig": "0102"}
    assert as_array["expandedJson"]["3 (attStmt)"] == {"value": [{"fmt": "none", "attStmt": {}}]}
