"""The ``cose`` format encodes a COSE_Key, whatever JSON spelling it comes in.

A COSE key's labels 1 and 3 are kty and alg. Read as a CTAP map they looked like
getAssertion members 1 (credential) and 3 (signature), and the key went to the
getAssertion-response builder. Now labels become integers, byte-string
parameters are decoded from the hex or base64url the decoder shows them in, and
the result is the COSE_Key's canonical CBOR.
"""
from __future__ import annotations

import json
import os

import cbor2
import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from tests.app.decoder.real_vectors import (
    MAKE_CREDENTIAL_RESPONSE,
    NONE_AUTH_DATA,
    NONE_WINDOWS_HELLO_AUTH_DATA,
)

_X, _Y = bytes(range(32)), bytes(range(32, 64))
_ES256 = {1: 2, 3: -7, -1: 1, -2: _X, -3: _Y}


def _encode(value) -> dict:
    return encode_payload_text(json.dumps(value), "COSE")


def _encoded_bytes(value) -> bytes:
    return bytes.fromhex(_encode(value)["data"]["binary"]["hex"])


def _credential_key(auth_data: bytes) -> bytes:
    """The COSE_Key bytes inside authData, read the way the spec lays them out."""

    id_length = int.from_bytes(auth_data[53:55], "big")
    start = 55 + id_length
    return auth_data[start : start + len(cbor2.dumps(cbor2.loads(auth_data[start:])))]


def test_a_cose_key_given_as_json_is_encoded_as_a_cose_key():
    response = _encode({"1": 2, "3": -7, "-1": 1, "-2": _X.hex(), "-3": _Y.hex()})

    assert response["success"] is True
    assert response["type"] == "COSE (COSE_Key)"
    assert bytes.fromhex(response["data"]["binary"]["hex"]) == cbor2.dumps(_ES256)


def test_labels_may_carry_their_names_and_bytes_may_be_base64url():
    response = _encode({"1 (kty)": 2, "3 (alg)": -7, "-1 (crv)": 1, "-2 (x)": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "-3 (y)": _Y.hex()})

    assert bytes.fromhex(response["data"]["binary"]["hex"]) == cbor2.dumps(_ES256)


def test_the_decoders_own_cose_key_round_trips_to_the_same_bytes():
    for auth_data in (NONE_AUTH_DATA, NONE_WINDOWS_HELLO_AUTH_DATA):
        decoded = decode_payload_text(auth_data.hex())
        cose = decoded["data"]["credential"]["publicKey"]["cose"]

        assert _encoded_bytes(cose) == _credential_key(auth_data)


def test_the_ctap_views_hex_cose_key_round_trips_to_the_same_bytes():
    decoded = decode_payload_text("00" + MAKE_CREDENTIAL_RESPONSE.hex())
    auth_data_view = decoded["data"]["ctapDecoded"]["makeCredentialResponse"]["2 (authData)"]
    cose = auth_data_view["attestedCredentialData"]["credentialPublicKey"]
    auth_data = bytes.fromhex(auth_data_view["raw"])

    assert _encoded_bytes(cose) == _credential_key(auth_data)


def test_an_ml_dsa_akp_key_round_trips():
    public_key = os.urandom(1952)
    akp = cbor2.dumps({1: 7, 3: -49, -1: public_key})
    auth_data = bytes(32) + b"\x41" + bytes(4) + bytes(16) + (2).to_bytes(2, "big") + b"id" + akp

    cose = decode_payload_text(auth_data.hex())["data"]["credential"]["publicKey"]["cose"]

    assert _encoded_bytes(cose) == akp


def test_the_decoders_public_key_block_encodes_its_cose_member_and_says_what_it_left():
    response = _encode({"cose": {"1": 2, "3": -7, "-1": 1, "-2": _X.hex(), "-3": _Y.hex()}, "alg": "ES256 (ECDSA)", "keyType": "EC2 (2)"})

    assert bytes.fromhex(response["data"]["binary"]["hex"]) == cbor2.dumps(_ES256)
    assert response["malformed"] == [
        "Encoded only cose; alg, keyType beside it were not encoded (the decoder's descriptions of the key)."
    ]


def test_a_compressed_ec2_point_keeps_its_boolean_y():
    assert _encoded_bytes({"1": 2, "3": -7, "-1": 1, "-2": _X.hex(), "-3": True}) == cbor2.dumps(
        {1: 2, 3: -7, -1: 1, -2: _X, -3: True}
    )


def test_key_ops_and_text_algorithm_values_are_kept_as_given():
    assert _encoded_bytes({"1": 4, "3": "A128GCM", "4": [3, "decrypt"], "-1": "00" * 16}) == cbor2.dumps(
        {1: 4, 3: "A128GCM", 4: [3, "decrypt"], -1: bytes(16)}
    )


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ({"3": -7, "-2": _X.hex()}, "needs kty"),
        ({"kty": 2}, "is not an integer label"),
        ({"1": 2, "-2": "not hex!"}, "is not hex or base64url"),
        ({"1": 2, "-2": 5}, "must be a byte string"),
        ({"1": 2, "-9": "abcd"}, "cannot be told apart as text or bytes"),
        ({"1": 2, "1 (kty)": 2}, "is given twice"),
        ({"1": 2, "4": []}, "key_ops (label 4) must be"),
        ({"1": 2, "-1": None}, "crv (label -1) must be"),
        ([1, 2], "is a JSON object"),
    ],
)
def test_what_cannot_be_encoded_as_a_cose_key_is_refused(key, message):
    with pytest.raises(ValueError, match=message.replace("(", r"\(").replace(")", r"\)")):
        _encode(key)


def test_an_unknown_label_with_an_integer_value_is_kept():
    assert _encoded_bytes({"1": 2, "-70000": 7}) == cbor2.dumps({1: 2, -70000: 7})


def test_the_parameter_tables_are_rfc_9052_9053_and_8230():
    from server.app.decoder import cose_tables

    assert {label: name for label, (name, _type) in cose_tables.COMMON_PARAMETERS.items()} == {
        1: "kty", 2: "kid", 3: "alg", 4: "key_ops", 5: "Base IV",
    }
    names = {
        kty: {label: name for label, (name, _type) in parameters.items()}
        for kty, parameters in cose_tables.KEY_TYPE_PARAMETERS.items()
    }
    assert names == {
        1: {-1: "crv", -2: "x", -4: "d"},
        2: {-1: "crv", -2: "x", -3: "y", -4: "d"},
        3: {-1: "n", -2: "e", -3: "d", -4: "p", -5: "q", -6: "dP", -7: "dQ", -8: "qInv", -9: "other",
            -10: "r_i", -11: "d_i", -12: "t_i"},
        4: {-1: "k"},
        7: {-1: "pub", -2: "priv"},
    }
