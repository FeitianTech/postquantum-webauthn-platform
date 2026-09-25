"""Map keys that JSON would spell alike are all shown, each with its type.

JSON spells every map key as text. The integer 1 and the text "1", or the byte
string h'01' and the text "01", are different CBOR keys with one JSON spelling,
and one entry used to replace the other. Now every view keeps both: where
nothing collides a key is spelled as before; where keys collide, each is spelled
with its type (1, "1" (text), h'01' (bytes)) and a ``json-key-collision``
finding names the map by offset and path.
"""
from __future__ import annotations

import cbor2
import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import extensions, get_info, keys
from tests.app.decoder import real_vectors as rv

_CLIENT_DATA_HASH = bytes(range(32))


def _decode(hex_text: str) -> dict:
    return decode_payload_text(hex_text)


def _collisions(result: dict) -> list[tuple[int, str, list[str]]]:
    return [
        (finding["offset"], finding["path"], finding["keys"])
        for finding in result["findings"]
        if finding["code"] == "json-key-collision"
    ]


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ({1: "a", "1": "b"}, {"1": "a", '"1" (text)': "b"}),
        ({b"\x01": "a", "01": "b"}, {"h'01' (bytes)": "a", '"01" (text)': "b"}),
        ({10: "a", b"\x10": "b"}, {"10": "a", "h'10' (bytes)": "b"}),
        ({True: "a", "true": "b"}, {"true (boolean)": "a", '"true" (text)': "b"}),
        ({1.5: "a", "1.5": "b"}, {"1.5 (float)": "a", '"1.5" (text)': "b"}),
        ({None: "a", "null": "b"}, {"null (null)": "a", '"null" (text)': "b"}),
        ({1: "a", "1": "b", b"\x01": "c", "01": "d"}, {"1": "a", '"1" (text)': "b", "h'01' (bytes)": "c", '"01" (text)': "d"}),
    ],
    ids=["int-text", "bytes-text", "int-bytes", "true-text", "float-text", "null-text", "two-groups"],
)
def test_colliding_keys_are_all_kept_and_spelled_with_their_type(message, expected):
    result = _decode(cbor2.dumps(message).hex())

    assert result["data"]["decodedValue"] == expected
    assert _collisions(result) == [(0, "$", list(expected))]


def test_the_finding_says_which_keys_share_which_spelling():
    finding = _decode(cbor2.dumps({1: "a", "1": "b"}).hex())["findings"][0]

    assert finding["category"] == "rendering"
    assert finding["message"] == (
        'map keys 1 and "1" (text) both read "1" as JSON keys; '
        "each is shown with its type so that neither entry replaces the other"
    )


def test_an_array_key_and_the_text_it_is_spelled_as_are_two_keys():
    # {[1, 2]: "a", "[1, 2]": "b"}
    result = _decode("a2" + "820102" + "6161" + "665b312c20325d" + "6162")

    assert result["data"]["decodedValue"] == {"[1, 2] (array)": "a", '"[1, 2]" (text)': "b"}
    assert len(_collisions(result)) == 1


def test_keys_that_do_not_collide_keep_their_plain_spelling():
    # {1: "a", "b": 2, h'0102': 3, true: 4}, written out: Python folds True into 1.
    result = _decode("a4" + "016161" + "616202" + "42010203" + "f504")

    assert result["data"]["decodedValue"] == {"1": "a", "b": 2, "0102": 3, "true": 4}
    assert _collisions(result) == []


def test_a_nested_map_is_reported_at_its_own_offset_and_path():
    # {"outer": [0, {1: "a", "1": "b"}]}: the inner map starts at byte 9.
    result = _decode(cbor2.dumps({"outer": [0, {1: "a", "1": "b"}]}).hex())

    assert result["data"]["decodedValue"] == {"outer": [0, {"1": "a", '"1" (text)': "b"}]}
    assert _collisions(result) == [(9, '${"outer"}[1]', ["1", '"1" (text)'])]


def test_a_duplicate_key_is_not_a_json_key_collision():
    # {1: 1, 1: 2} is one key written twice; canonical.py reports that.
    result = _decode("a201010102")

    assert _collisions(result) == []
    assert [finding["code"] for finding in result["findings"]] == ["duplicate-map-key"]


def test_a_ctap_request_keeps_a_text_key_beside_the_member_it_resembles():
    message = {1: _CLIENT_DATA_HASH, 2: {"id": "example.com"}, 3: {"id": b"u", "name": "u"}, 4: [], "1": "x"}

    result = _decode("01" + cbor2.dumps(message).hex())
    request = result["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert request["1 (clientDataHash)"] == _CLIENT_DATA_HASH.hex()
    assert request['"1" (text)'] == "x"
    assert _collisions(result) == [(1, "$", ["1", '"1" (text)'])]


def test_an_unknown_ctap_member_and_its_text_twin_are_both_shown():
    message = {1: "example.com", 2: _CLIENT_DATA_HASH, 16: "integer", "16": "text"}

    result = _decode("02" + cbor2.dumps(message).hex())
    request = result["data"]["ctapDecoded"]["getAssertionRequest"]

    assert request["16"] == "integer"
    assert request['"16" (text)'] == "text"


def test_a_colliding_user_entity_member_is_kept():
    user = {"id": b"\x01", "name": "u", 5: "integer", "5": "text"}
    message = {1: _CLIENT_DATA_HASH, 2: {"id": "example.com"}, 3: user, 4: []}

    request = _decode("01" + cbor2.dumps(message).hex())["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert request["3 (user)"]["5"] == "integer"
    assert request["3 (user)"]['"5" (text)'] == "text"


def test_an_attestation_statement_with_colliding_keys_decodes_instead_of_failing():
    attestation = rv.attestation_object("none", {1: "a", "1": "b"}, rv.NONE_AUTH_DATA)

    result = _decode(attestation.hex())

    assert result["data"]["attestationObject"]["attStmt"] == {"1": "a", '"1" (text)': "b"}
    members = result["data"]["attestationStatementDecoded"]["notInSyntax"]["members"]
    assert members == {"1": "a", '"1" (text)': "b"}
    assert [(path, found) for _offset, path, found in _collisions(result)] == [('${"attStmt"}', ["1", '"1" (text)'])]


def test_the_endpoint_serializes_an_attestation_statement_with_mixed_key_types(client):
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {1: "a", "1": "b", 2.5: "c"}, "authData": rv.NONE_AUTH_DATA})

    response = client.post("/api/decode", json={"payload": attestation.hex()})

    assert response.status_code == 200
    assert response.get_json()["data"]["attestationObject"]["attStmt"] == {"1": "a", '"1" (text)': "b", "2.5": "c"}


def test_a_collision_inside_authenticator_data_is_located_there():
    cose_key = cbor2.dumps({1: 2, 3: -7, "1": "text"})
    auth_data = bytes(32) + b"\x41" + bytes(4) + bytes(16) + b"\x00\x01" + b"\xaa" + cose_key

    result = _decode(auth_data.hex())

    assert _collisions(result) == [(56, "$<credentialPublicKey>", ["1", '"1" (text)'])]


def test_get_info_keeps_a_byte_string_key_beside_its_text_twin():
    interpreted = get_info.interpret_get_info({1: ["FIDO_2_1"], 3: bytes(16), b"\x01": "bytes", "01": "text"})

    note = "not a member: CTAP 2.2 numbers members with integer keys"
    assert interpreted["h'01' (bytes)"] == {"value": "bytes", "note": note}
    assert interpreted['"01" (text)'] == {"value": "text", "note": note}


def test_get_info_options_keep_colliding_option_keys():
    options = get_info.interpret_get_info({1: ["FIDO_2_1"], 3: bytes(16), 4: {b"\x01": True, "01": False}})["4 (options)"]

    assert options["h'01' (bytes)"]["value"] is True
    assert options['"01" (text)']["value"] is False


def test_extension_entries_keep_colliding_identifiers():
    block = extensions.block({b"\x01": 1, "01": 2}, role=extensions.MAKE_CREDENTIAL_INPUT, location="x", path="$")

    assert set(block["entries"]) == {"h'01' (bytes)", '"01" (text)'}


def test_json_keys_never_returns_two_alike_whatever_decorate_does():
    assert keys.json_keys([1, 2], lambda key, text: "same") == ["same", "same #2"]
    assert keys.json_keys([1, "1", '"1" (text)']) == ["1", '"1" (text)', '"\\"1\\" (text)" (text)']


def test_a_map_spelled_once_is_not_spelled_again():
    # The decoder passes one map through json_items several times (the decoded
    # value, then the response); a label from an earlier pass is kept as it is.
    from server.app.decoder.decode import keys
    from server.app.decoder.decode.cbor_parser import CborDiagnostic

    value = {1: "a", "1": "b", b"\x01": "c", "01": "d", CborDiagnostic("true", "boolean"): "e", "true": "f"}
    once = keys.make_hex_only(value)

    assert all(isinstance(label, keys.JsonLabel) for label in once)
    assert keys.stringify_mapping_keys(keys.make_hex_only(once)) == once
    assert keys.json_ready(once) == once
    assert list(once) == ["1", '"1" (text)', "h'01' (bytes)", '"01" (text)', "true (boolean)", '"true" (text)']
