"""The byte before a CTAP message says what the message is.

A command byte is followed by that command's parameters, whatever their shape.
A status byte says only that a response follows. ``ctapDecoded`` and
``expandedJson`` are two views of one reading, so they always name the same kind.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from fido2 import cbor

CLIENT_DATA_HASH = bytes(range(32))


def _decode(data: bytes) -> dict[str, Any]:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    return decode_module.decode_payload_text(data.hex())


def _authenticator_data() -> bytes:
    return hashlib.sha256(b"example.com").digest() + b"\x01" + (5).to_bytes(4, "big")


def test_a_get_assertion_request_without_an_allow_list_is_a_get_assertion_request():
    result = _decode(b"\x02" + cbor.encode({1: "example.com", 2: CLIENT_DATA_HASH}))

    assert result["type"] == "CBOR (GET_ASSERTION command; GetAssertion request)"
    request = result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert request["1 (rpId)"] == "example.com"
    assert request["2 (clientDataHash)"] == CLIENT_DATA_HASH.hex()
    assert result["data"]["expandedJson"] == request
    assert "makeCredentialResponse" not in result["data"]["ctapDecoded"]


def test_the_command_byte_wins_over_a_body_shaped_like_a_response():
    body = cbor.encode({1: "packed", 2: _authenticator_data(), 3: {}})

    result = _decode(b"\x02" + body)

    assert result["type"] == "CBOR (GET_ASSERTION command; GetAssertion request)"
    request = result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert request["1 (rpId)"] == "packed"
    assert result["data"]["expandedJson"] == request


def test_a_make_credential_request_missing_its_user_is_still_a_make_credential_request():
    body = cbor.encode({1: CLIENT_DATA_HASH, 2: {"id": "example.com"}, 4: [{"type": "public-key", "alg": -7}]})

    result = _decode(b"\x01" + body)

    assert result["type"] == "CBOR (MAKE_CREDENTIAL command; MakeCredential request)"
    request = result["data"]["ctapDecoded"]["makeCredentialRequest"]
    assert request["1 (clientDataHash)"] == CLIENT_DATA_HASH.hex()
    assert "3 (user)" not in request
    assert result["data"]["expandedJson"] == request


def test_a_command_without_a_parameter_table_is_not_labelled_as_another_command():
    # authenticatorClientPIN, getPinRetries: {1: pinUvAuthProtocol, 2: subCommand}
    result = _decode(b"\x06" + cbor.encode({1: 2, 2: 1}))

    assert result["type"] == "CBOR (CLIENT_PIN command)"
    assert "ctapDecoded" not in result["data"]
    assert "expandedJson" not in result["data"]
    assert result["data"]["decodedValue"] == {"1": 2, "2": 1}


def test_a_status_byte_is_never_followed_by_a_request():
    result = _decode(b"\x00" + cbor.encode({1: "example.com", 2: CLIENT_DATA_HASH}))

    assert result["type"] == "CBOR (SUCCESS status)"
    assert "ctapDecoded" not in result["data"]
    assert "expandedJson" not in result["data"]


def test_without_a_prefix_byte_both_views_name_the_same_kind():
    # 0xa2 is no CTAP code, so the whole input is the message.
    result = _decode(cbor.encode({1: "example.com", 2: CLIENT_DATA_HASH}))

    assert list(result["data"]["ctapDecoded"]) == ["getAssertionRequest"]
    assert result["data"]["expandedJson"] == result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert result["type"] == "CBOR (GetAssertion request)"
