"""JSON the decoder reads that repeats an object key is reported, not silently cut.

``json.loads`` keeps the later value and drops the earlier one without a word;
the decoder keeps the same value, and a ``duplicate-json-key`` finding names the
key's path, the value kept and each value dropped. That matters most in client
data, where two parsers can disagree about which ``challenge`` or ``origin``
counts.
"""
from __future__ import annotations

import base64
import json

from server.app.decoder import decode_payload_text


def _duplicates(result: dict) -> list[dict]:
    return [finding for finding in result["findings"] if finding["code"] == "duplicate-json-key"]


def test_a_repeated_key_names_its_path_the_value_kept_and_the_value_dropped():
    result = decode_payload_text('{"a":1,"a":2}')

    assert result["data"] == {"json": {"a": 2}}
    (finding,) = _duplicates(result)
    assert finding == {
        "code": "duplicate-json-key",
        "category": "json",
        "offset": None,
        "path": '${"a"}',
        "key": "a",
        "kept": 2,
        "dropped": [1],
        "message": 'object key "a" appears twice; the decoded value keeps the later value, 2, and drops 1',
    }


def test_repeated_keys_are_found_at_any_depth():
    result = decode_payload_text('{"x": {"a": 1, "a": [2], "a": {"b": 3}}, "list": [{"k": "v", "k": "w"}]}')

    assert result["data"]["json"] == {"x": {"a": {"b": 3}}, "list": [{"k": "w"}]}
    found = {finding["path"]: finding for finding in _duplicates(result)}
    assert set(found) == {'${"x"}{"a"}', '${"list"}[0]{"k"}'}
    assert (found['${"x"}{"a"}']["kept"], found['${"x"}{"a"}']["dropped"]) == ({"b": 3}, [1, [2]])
    assert "appears 3 times; the decoded value keeps the last value" in found['${"x"}{"a"}']["message"]
    assert (found['${"list"}[0]{"k"}']["kept"], found['${"list"}[0]{"k"}']["dropped"]) == ("w", ["v"])


def test_json_without_a_repeated_key_is_unchanged():
    assert decode_payload_text('{"a": 1, "b": {"a": 2}}')["findings"] == []


def test_utf8_json_bytes_report_a_repeated_key_too():
    result = decode_payload_text(b'{"a":1,"a":2}'.hex())

    assert result["data"] == {"json": {"a": 2}}
    assert [finding["path"] for finding in _duplicates(result)] == ['${"a"}']


CLIENT_DATA = (
    '{"type": "webauthn.create", "challenge": "AAAA", "origin": "https://evil.example", '
    '"origin": "https://example.com"}'
)


def test_client_data_that_repeats_its_origin_says_which_one_it_shows():
    result = decode_payload_text(CLIENT_DATA.encode().hex())

    assert result["type"] == "WebAuthn client data"
    (finding,) = _duplicates(result)
    assert (finding["path"], finding["kept"], finding["dropped"]) == (
        '${"origin"}', "https://example.com", ["https://evil.example"]
    )


def test_a_credential_whose_client_data_repeats_a_key_reports_it_in_that_field():
    credential = {
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {"clientDataJSON": base64.urlsafe_b64encode(CLIENT_DATA.encode()).decode().rstrip("=")},
    }

    result = decode_payload_text(json.dumps(credential))

    (finding,) = _duplicates(result)
    assert (finding["source"], finding["path"]) == ("response.clientDataJSON", '${"origin"}')


def test_the_endpoint_answers_a_finding_without_an_offset(client):
    response = client.post("/api/decode", json={"payload": '{"a":1,"a":2}'})

    assert response.status_code == 200
    assert response.get_json()["findings"][0]["offset"] is None
