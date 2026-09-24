"""CTAP 2.2 section 8, "Message Encoding", limits nesting to four levels.

"the depth of nested CBOR structures used by all message encodings is limited
to at most four (4) levels of any combination of CBOR maps and/or CBOR arrays."
The decoder reports the first map or array at a fifth level, once, and still
decodes the value in full.
"""
from __future__ import annotations

import cbor2

from server.app.decoder import decode_payload_text


def _depth_findings(value) -> list[dict]:
    result = decode_payload_text(cbor2.dumps(value).hex())
    return [finding for finding in result["findings"] if finding["code"] == "nesting-depth"]


def test_four_levels_are_allowed():
    assert _depth_findings({1: [{2: [1, 2]}]}) == []


def test_a_fifth_level_is_reported_at_its_offset_and_path():
    encoded = cbor2.dumps({1: [{2: [[7]]}]})

    result = decode_payload_text(encoded.hex())
    (finding,) = [finding for finding in result["findings"] if finding["code"] == "nesting-depth"]

    # a1 01 81 a1 02 81 81 07: the innermost array starts at offset 6.
    assert encoded.hex() == "a10181a102818107"
    assert finding["offset"] == 6
    assert finding["path"] == "${1}[0]{2}[0]"
    assert finding["category"] == "limit"
    assert "5 levels" in finding["message"]
    # Reported, not refused: the value is decoded in full.
    assert result["data"]["decodedValue"] == {"1": [{"2": [[7]]}]}


def test_deeper_nesting_is_reported_once_per_fifth_level_container():
    # map > array > array > array > two arrays at level 5, one holding a sixth.
    findings = _depth_findings({1: [[[[1], [[2]]]]]})

    assert [finding["path"] for finding in findings] == ["${1}[0][0][0]", "${1}[0][0][1]"]


def test_a_map_used_as_a_key_counts_as_a_level():
    # CBOR allows a map as a map key; it nests like any other map.
    encoded = bytes.fromhex("a1" "01" "81" "81" "a1" "a1" "0102" "03")
    findings = decode_payload_text(encoded.hex())["findings"]

    assert [finding["path"] for finding in findings if finding["code"] == "nesting-depth"] == ["${1}[0][0]{map[1]}"]


def test_tags_do_not_count_as_levels():
    tagged = cbor2.CBORTag(24, [[[[1]]]])

    assert _depth_findings(tagged) == []
