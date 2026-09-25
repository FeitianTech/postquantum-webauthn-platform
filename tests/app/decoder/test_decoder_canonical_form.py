"""Every decode reports where the CBOR is not in CTAP2 canonical form.

The findings say what, where (the byte offset, counted from the first input
byte) and on which item (the path); they never change the decoded value.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from fido2 import cbor
from server.app.decoder import decode_payload_text


def _decode(hex_text: str) -> dict[str, Any]:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    return decode_module.decode_payload_text(hex_text)


def _located(result: dict[str, Any]) -> list[tuple[str, int, str]]:
    return [(finding["code"], finding["offset"], finding["path"]) for finding in result["findings"]]


def test_a_duplicate_map_key_is_reported_with_both_offsets():
    # {1: 1, 1: 2}: the second entry used to replace the first without a word.
    result = _decode("a201010102")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("duplicate-map-key", 3, "${1}")]
    assert result["findings"][0]["message"] == (
        "map key 1 appears twice (first at offset 1); the decoded value keeps this later entry, "
        "and drops the earlier value 1 (offset 2)"
    )
    assert result["findings"][0]["category"] == "canonical"
    # The earlier entry is not lost: the finding carries it, and the EDN shows both.
    assert result["findings"][0]["earlier"] == [{"offset": 1, "valueOffset": 2, "key": "1", "value": "1"}]
    assert result["findings"][0]["kept"] == "later"
    assert result["findings"][0]["key"] == "1"
    assert result["data"]["edn"] == "{1: 1, 1: 2}"


def test_a_key_repeated_three_times_is_one_finding_at_the_entry_kept():
    # {1: "a", 2: 0, 1: "b", 1: [1, 2]}
    result = _decode("a4 01 6161 02 00 01 6162 01 820102".replace(" ", ""))

    assert result["data"]["decodedValue"] == {"1": [1, 2], "2": 0}
    (finding,) = [finding for finding in result["findings"] if finding["code"] == "duplicate-map-key"]
    assert (finding["offset"], finding["path"]) == (9, "${1}")
    assert finding["earlier"] == [
        {"offset": 1, "valueOffset": 2, "key": "1", "value": '"a"'},
        {"offset": 6, "valueOffset": 7, "key": "1", "value": '"b"'},
    ]
    assert finding["message"] == (
        'map key 1 appears 3 times (first at offset 1); the decoded value keeps this last entry, '
        'and drops the earlier values "a" (offset 2), "b" (offset 7)'
    )


def test_a_duplicate_inside_a_value_the_decoded_value_drops_says_it_keeps_neither_entry():
    # {1: {2: 1, 2: 2}, 1: {2: 3, 2: 4}}: the first inner map is dropped whole.
    result = _decode("a2 01 a2 0201 0202 01 a2 0203 0204".replace(" ", ""))

    assert result["data"]["decodedValue"] == {"1": {"2": 4}}
    found = {finding["offset"]: finding for finding in result["findings"] if finding["code"] == "duplicate-map-key"}
    assert sorted(found) == [5, 7, 11]
    # Before: offset 5 said "the decoded value keeps this later entry", the value 2 it does not hold.
    assert found[5]["kept"] is None
    assert "the decoded value keeps none of them: the map is inside a value it drops" in found[5]["message"]
    assert (found[7]["kept"], found[11]["kept"]) == ("later", "later")
    assert all(finding["message"] in result["malformed"] for finding in found.values())


@pytest.mark.parametrize(
    ("hex_text", "decoded", "located"),
    [
        # Two keys the lenient parser could not read, the same bytes: one entry, and now said so.
        ("a2 ff01 ff02", {"invalid(h'ff')": 2}, [("duplicate-map-key", 3, "${invalid(h'ff')}")]),
        ("a2 1c01 1c02", {"invalid(h'1c')": 2}, [("duplicate-map-key", 3, "${invalid(h'1c')}")]),
        # A duplicate inside the value of an unreadable key is checked like any other.
        ("a1 ff a2 0101 0102", {"invalid(h'ff')": {"1": 2}}, [("duplicate-map-key", 5, "${invalid(h'ff')}{1}")]),
    ],
)
def test_a_lenient_read_reports_duplicates_under_keys_it_could_not_read(hex_text, decoded, located):
    decode_module = pytest.importorskip("server.app.decoder.decode")
    result = decode_module.decode_payload_text(hex_text.replace(" ", ""), lenient=True)

    assert result["data"]["decodedValue"] == decoded
    assert [entry for entry in _located(result) if entry[0] == "duplicate-map-key"] == located


def test_a_duplicate_label_inside_a_credential_public_key_is_located_in_the_input():
    from server.app.decoder import edn

    # A COSE key {1: 2, 1: 2, 3: -7} inside authData inside an attestation object.
    cose = bytes.fromhex("a3 01 02 01 02 03 26".replace(" ", ""))
    auth_data = bytes(32) + b"\x41" + bytes(4) + bytes(16) + b"\x00\x01" + b"\x07" + cose
    attestation_object = edn.encode(f'{{"fmt": "none", "attStmt": {{}}, "authData": h\'{auth_data.hex()}\'}}')
    cose_start = attestation_object.index(auth_data) + 56

    result = _decode(attestation_object.hex())

    (finding,) = [finding for finding in result["findings"] if finding["code"] == "duplicate-map-key"]
    assert finding["offset"] == cose_start + 3
    assert finding["path"] == '${"authData"}<credentialPublicKey>{1}'
    assert finding["earlier"] == [{"offset": cose_start + 1, "valueOffset": cose_start + 2, "key": "1", "value": "2"}]
    # The message quotes the same input offsets, not ones counted from authData.
    assert finding["message"] == (
        f"map key 1 appears twice (first at offset {cose_start + 1}); the decoded value keeps this later entry, "
        f"and drops the earlier value 2 (offset {cose_start + 2})"
    )
    assert finding["message"] in result["malformed"]


def test_a_duplicate_label_inside_a_ctap_response_is_quoted_at_its_input_offsets():
    # MAKE_CREDENTIAL's response: status 00, then {1: "none", 2: authData, 3: {}}.
    cose = bytes.fromhex("a3 01 02 01 02 03 26".replace(" ", ""))
    auth_data = bytes(32) + b"\x41" + bytes(4) + bytes(16) + b"\x00\x01" + b"\x07" + cose
    response = b"\x00" + cbor.encode({1: "none", 2: auth_data, 3: {}})
    cose_start = response.index(auth_data) + 56

    result = _decode(response.hex())

    (finding,) = [finding for finding in result["findings"] if finding["code"] == "duplicate-map-key"]
    assert (finding["offset"], finding["earlier"][0]["offset"]) == (cose_start + 3, cose_start + 1)
    assert f"first at offset {cose_start + 1});" in finding["message"]
    assert finding["message"].endswith(f"drops the earlier value 2 (offset {cose_start + 2})")


def test_a_duplicate_inside_chunked_authenticator_data_points_at_the_string():
    from server.app.decoder import edn

    cose = bytes.fromhex("a3 01 02 01 02 03 26".replace(" ", ""))
    auth_data = bytes(32) + b"\x41" + bytes(4) + bytes(16) + b"\x00\x01" + b"\x07" + cose
    half = len(auth_data) // 2
    text = f'{{"fmt": "none", "attStmt": {{}}, "authData": (_ h\'{auth_data[:half].hex()}\', h\'{auth_data[half:].hex()}\')}}'
    attestation_object = edn.encode(text)
    string_offset = attestation_object.index(b"\x5f")

    result = _decode(attestation_object.hex())

    (finding,) = [finding for finding in result["findings"] if finding["code"] == "duplicate-map-key"]
    assert finding["offset"] == string_offset
    assert finding["earlier"][0]["offset"] == finding["earlier"][0]["valueOffset"] == string_offset
    assert f"first at offset {string_offset});" in finding["message"]
    assert f"drops the earlier value 2 (offset {string_offset}) (inside an indefinite-length" in finding["message"]


def test_a_non_shortest_integer_is_reported_where_it_is_written():
    # {1: 2} with the key written as 18 01.
    result = _decode("a1180102")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("non-shortest-integer", 1, "${1}")]
    assert result["findings"][0]["message"] == (
        "integer 1 has a 2-byte head (18 01); CTAP2 requires the shortest, 1 byte"
    )


def test_an_indefinite_length_map_is_reported():
    result = _decode("bf0102ff")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("indefinite-length", 0, "$")]


@pytest.mark.parametrize(
    ("hex_text", "located"),
    [
        # {2: 0, 1: 0}: the same major type and length, so bytewise.
        ("a202000100", [("map-key-order", 3, "${1}")]),
        # {"a": 0, 1: 0}: major type 3 before major type 0.
        ("a26161000100", [("map-key-order", 4, "${1}")]),
        # {24: 0, 5: 0}: 18 18 is longer than 05, so 5 sorts first.
        ("a21818000500", [("map-key-order", 4, "${5}")]),
        # {"b": 0, "a": 0}
        ("a26162006161 00".replace(" ", ""), [("map-key-order", 4, '${"a"}')]),
        # {-1: 0, 24: 0}: 18 18 (major 0) before 20 (major 1), whatever the lengths.
        ("a22000181800", [("map-key-order", 3, "${24}")]),
    ],
)
def test_map_keys_out_of_ctap2_order_are_reported(hex_text, located):
    assert _located(_decode(hex_text)) == located


def test_map_keys_in_ctap2_order_are_not_reported():
    # {5: 0, 24: 0, -1: 0, h'': 0, "": 0, "a": 0}
    result = _decode("a60500181800200040006000616100")

    # h'' and "" are both "" as JSON keys: reported, but not a canonical-form problem.
    assert _located(result) == [("json-key-collision", 0, "$")]


def test_a_key_written_twice_in_different_lengths_is_one_key_twice():
    # {1: 0, 1: 0}, the second 1 written as 18 01.
    result = _decode("a2010018 0100".replace(" ", ""))

    assert _located(result) == [("non-shortest-integer", 3, "${1}"), ("duplicate-map-key", 3, "${1}")]


@pytest.mark.parametrize(
    ("hex_text", "code", "message"),
    [
        ("5801aa", "non-shortest-length", "byte string of length 1 has a 2-byte head (58 01)"),
        # (Hex made only of digits would be read as a JSON number.)
        ("7900017a", "non-shortest-length", "text string of length 1 has a 3-byte head (79 00 01)"),
        ("9801f6", "non-shortest-length", "array of length 1 has a 2-byte head (98 01)"),
        ("3a00000000", "non-shortest-integer", "integer -1 has a 5-byte head (3a 00 00 00 00)"),
        ("c101", "tag", "tag 1; CTAP2 canonical CBOR has no tags"),
        ("5f4161ff", "indefinite-length", "indefinite-length byte string; CTAP2 requires definite lengths"),
    ],
)
def test_other_canonical_form_violations_are_reported(hex_text, code, message):
    finding = _decode(hex_text)["findings"][0]

    assert finding["code"] == code
    assert finding["message"].startswith(message)


def test_findings_in_nested_items_carry_their_path():
    # {1: [0, {"x": 18 05}]}
    result = _decode("a101820 0a1617818 05".replace(" ", ""))

    assert _located(result) == [("non-shortest-integer", 7, '${1}[1]{"x"}')]


def test_findings_never_change_the_decoded_value():
    canonical = _decode("a2010203 04".replace(" ", ""))["data"]["decodedValue"]
    # The same map written with long heads, indefinite length and keys reversed.
    other = _decode("bf1803041801 02ff".replace(" ", ""))

    assert other["data"]["decodedValue"] == canonical
    assert {finding["code"] for finding in other["findings"]} == {
        "indefinite-length",
        "non-shortest-integer",
        "map-key-order",
    }


def test_findings_are_listed_in_byte_order_with_trailing_bytes_last():
    result = _decode("a2020001 00ff".replace(" ", ""))

    assert [finding["offset"] for finding in result["findings"]] == [3, 5]
    assert [finding["code"] for finding in result["findings"]] == ["map-key-order", "trailing-bytes"]
    trailing = result["findings"][1]
    assert (trailing["category"], trailing["length"], trailing["hex"]) == ("trailing", 1, "ff")


def test_malformed_lists_the_findings_about_form_and_only_those():
    # {1: 1, 1: 2}: a duplicate key is not canonical, so it is in malformed.
    result = _decode("a201010102")

    assert result["malformed"] == [finding["message"] for finding in result["findings"]]


@pytest.mark.parametrize(
    ("payload", "code", "in_malformed"),
    [
        ("a2 01 01 01 02", "duplicate-map-key", True),  # canonical
        ("1801", "non-shortest-integer", True),  # canonical
        ("a1 01 02 ff", "trailing-bytes", True),  # trailing: RFC 8949 appendix F, "too much data"
        ("a2 01 6161 6131 6162", "json-key-collision", False),  # how the view spells keys
        ("8101", "ambiguous-input", False),  # which reading of the input was taken
        ("8181818181 01", "nesting-depth", False),  # a CTAP limit, not a matter of form
        ("41ab", "ctap-prefix-not-read", False),
    ],
)
def test_a_finding_is_in_malformed_only_when_it_is_about_form(payload, code, in_malformed):
    result = _decode(payload.replace(" ", ""))
    findings = [finding for finding in result["findings"] if finding["code"] == code]

    assert findings
    assert all((finding["message"] in result["malformed"]) is in_malformed for finding in findings)


def test_a_note_alone_leaves_malformed_empty():
    result = decode_payload_text('{"a": 1, "a": 2}')

    assert [finding["code"] for finding in result["findings"]] == ["duplicate-json-key"]
    assert result["malformed"] == []


def test_a_ctap_message_is_checked_with_offsets_counting_its_prefix_byte():
    # MAKE_CREDENTIAL, then {2: ..., 1: ...}: key 1 is out of order.
    rp = cbor.encode({"id": "example.com"})
    body = b"\xa2" + cbor.encode(2) + rp + cbor.encode(1) + cbor.encode(bytes(32))

    result = _decode((b"\x01" + body).hex())

    key_one_offset = 1 + 1 + 1 + len(rp)
    assert _located(result) == [("map-key-order", key_one_offset, "${1}")]


def test_an_attestation_object_is_checked_too():
    auth_data = hashlib.sha256(b"example.com").digest() + b"\x01" + (5).to_bytes(4, "big")
    # authData before fmt: "authData" is longer than "fmt", so it sorts after it.
    attestation = (
        b"\xa3"
        + cbor.encode("authData")
        + cbor.encode(auth_data)
        + cbor.encode("fmt")
        + cbor.encode("none")
        + cbor.encode("attStmt")
        + cbor.encode({})
    )

    result = _decode(attestation.hex())

    assert result["type"] == "Attestation object"
    assert [finding["code"] for finding in result["findings"]] == ["map-key-order"]
    assert result["findings"][0]["path"] == '${"fmt"}'


def test_the_codec_endpoint_returns_findings_and_the_decode_mode(client):
    response = client.post("/api/codec", json={"payload": "a201010102", "mode": "decode"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["decodeMode"] == "strict"
    assert [finding["code"] for finding in body["findings"]] == ["duplicate-map-key"]


def test_canonical_input_has_no_findings():
    result = _decode(cbor.encode({1: "packed", 2: b"\x01", 3: {"alg": -7, "sig": b"\x02"}}).hex())

    assert result["findings"] == []
    assert result["malformed"] == []
