"""JSON input holding NaN, Infinity or -Infinity: not JSON under RFC 8259, which Python's reader accepts.

Read strictly, such text is refused with the offset and path of the first; read
leniently, each is a finding and is shown as the decoder shows a CBOR NaN,
``{"diagnostic": "NaN"}``. The encoder refuses it, pointing at EDN. A number
beyond the range of a double (``1e400``), which Python's reader makes an
infinity, is refused or read the same way, shown as written. Every answer is
read here as the browser's ``response.json()`` reads it: strictly.
"""
from __future__ import annotations

import base64
import io
import json

import pytest

from server.app import visitor_session
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.storage import github_mirror

_CONSTANTS = '{"a": NaN, "b": [Infinity, -Infinity]}'
_REFUSED = (
    "Not JSON at offset {offset} ({path}): NaN is not JSON: RFC 8259 has no NaN or Infinity. The decoder "
    "reads it when asked to read leniently; EDN writes it (NaN, Infinity, -Infinity)."
)


def _strict(text: str):
    def refuse(constant):
        raise ValueError(f"{constant} in an answer")

    return json.loads(text, parse_constant=refuse)


def _codec(client, **body):
    response = client.post("/api/codec", json=body)
    return response.status_code, _strict(response.get_data(as_text=True))


def test_decoding_json_with_nan_is_refused_with_its_offset_and_path(client):
    # Blank space before the input counts: the offset is into the input as sent.
    status, body = _codec(client, payload="  " + _CONSTANTS)

    assert status == 422
    assert body == {"error": _REFUSED.format(offset=8, path='${"a"}'), "offset": 8, "path": '${"a"}'}


def test_decoding_json_with_nan_leniently_reads_it_and_says_where(client):
    status, body = _codec(client, payload=_CONSTANTS, lenient=True)

    assert status == 200
    assert body["decodeMode"] == "lenient"
    assert body["data"]["json"] == {
        "a": {"diagnostic": "NaN"},
        "b": [{"diagnostic": "Infinity"}, {"diagnostic": "-Infinity"}],
    }
    assert [(finding["code"], finding["offset"], finding["path"]) for finding in body["findings"]] == [
        ("json-nan-or-infinity", 6, '${"a"}'),
        ("json-nan-or-infinity", 17, '${"b"}[0]'),
        ("json-nan-or-infinity", 27, '${"b"}[1]'),
    ]
    assert len(body["malformed"]) == 3


def test_nan_inside_a_json_string_is_text(client):
    status, body = _codec(client, payload='{"a": "NaN, Infinity \\" -Infinity"}')

    assert status == 200
    assert body["findings"] == []


def test_json_bytes_with_nan_count_the_offset_in_bytes(client):
    status, body = _codec(client, payload='{"é": NaN}'.encode().hex())

    assert status == 422
    assert (body["offset"], body["path"]) == (7, '${"é"}')


@pytest.mark.parametrize("target", ["CBOR", "JSON"])
def test_encoding_json_with_nan_is_refused(client, target):
    status, body = _codec(client, payload=_CONSTANTS, mode="encode", format=target)

    assert status == 422
    assert body["error"] == _REFUSED.format(offset=6, path='${"a"}')


def _credential(client_data: bytes) -> str:
    return json.dumps(
        {
            "id": "AAAA",
            "type": "public-key",
            "response": {"clientDataJSON": base64.urlsafe_b64encode(client_data).decode().rstrip("=")},
        }
    )


_CLIENT_DATA = b'{"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "n": NaN}'


def test_client_data_with_nan_in_a_credential_does_not_decode(client):
    status, body = _codec(client, payload=_credential(_CLIENT_DATA))

    assert status == 200
    (finding,) = body["findings"]
    assert (finding["code"], finding["offset"], finding["path"], finding["source"]) == (
        "parse-error", 74, '${"n"}', "response.clientDataJSON"
    )


def test_client_data_with_nan_in_a_credential_is_read_leniently_and_said_so(client):
    status, body = _codec(client, payload=_credential(_CLIENT_DATA), lenient=True)

    assert status == 200
    (finding,) = body["findings"]
    assert (finding["code"], finding["offset"], finding["source"]) == (
        "json-nan-or-infinity", 74, "response.clientDataJSON"
    )
    assert body["data"]["clientDataJSON"]["origin"] == "https://x"


def test_an_uploaded_metadata_file_with_nan_is_refused(client, monkeypatch):
    saved = []
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda payload: [payload])
    monkeypatch.setattr(github_mirror, "queue_uploaded_metadata_files", lambda _files: None)
    monkeypatch.setattr(mds_uploads, "save_session_metadata_item", lambda payload, original_filename=None: saved.append(payload))
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda _item: {"storedFilename": "custom.json"})

    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(b'{"metadataStatement": {"n": NaN}}'), "custom.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert _strict(response.get_data(as_text=True)) == {
        "items": [],
        "errors": ["custom.json: NaN is not JSON (RFC 8259 has no NaN or Infinity)"],
    }
    assert saved == []


def test_the_bytes_of_nan_read_leniently_are_json_text_with_its_nan_noted(client):
    # Hex 4e614e is the bytes "NaN": JSON only when read leniently, and no other reading.
    result = client.post("/api/codec", json={"payload": "4e614e", "mode": "decode", "lenient": True}).get_json()

    assert result["type"] == "JSON"
    assert [finding["code"] for finding in result["findings"]] == ["json-nan-or-infinity"]


_OUT_OF_RANGE = '{"a": [1.5, 1e400], "b": -2E+999}'
_OUT_OF_RANGE_REFUSED = (
    "Number out of range at offset {offset} ({path}): 1e400 is beyond the range of a double. The decoder "
    "reads it, as written, when asked to read leniently."
)


def test_decoding_json_with_a_number_beyond_a_double_is_refused_with_its_offset_and_path(client):
    status, body = _codec(client, payload="  " + _OUT_OF_RANGE)

    assert status == 422
    assert body == {
        "error": _OUT_OF_RANGE_REFUSED.format(offset=14, path='${"a"}[1]'),
        "offset": 14,
        "path": '${"a"}[1]',
    }


def test_decoding_json_with_a_number_beyond_a_double_leniently_shows_it_as_written(client):
    status, body = _codec(client, payload=_OUT_OF_RANGE, lenient=True)

    assert status == 200
    assert body["data"]["json"] == {"a": [1.5, {"diagnostic": "1e400"}], "b": {"diagnostic": "-2E+999"}}
    assert [(finding["code"], finding["offset"], finding["path"]) for finding in body["findings"]] == [
        ("json-number-out-of-range", 12, '${"a"}[1]'),
        ("json-number-out-of-range", 25, '${"b"}'),
    ]
    assert len(body["malformed"]) == 2


def test_a_long_number_beyond_a_double_is_cut_short_in_its_sentence(client):
    number = "1" + "0" * 400 + ".5"
    status, body = _codec(client, payload=f"[{number}]")

    assert status == 422
    assert body["error"].startswith(f"Number out of range at offset 1 ($[0]): {number[:29]}... is beyond")


def test_json_bytes_with_a_number_beyond_a_double_count_the_offset_in_bytes(client):
    status, body = _codec(client, payload='{"é": 1e400}'.encode().hex())

    assert status == 422
    assert (body["offset"], body["path"]) == (7, '${"é"}')


@pytest.mark.parametrize("target", ["CBOR", "JSON", "COSE"])
def test_encoding_json_with_a_number_beyond_a_double_is_refused(client, target):
    status, body = _codec(client, payload='{"1": 2, "-1": 1e400}', mode="encode", format=target)

    assert status == 422
    assert body["error"].startswith('Number out of range at offset 15 (${"-1"}): 1e400 is beyond the range')


def test_client_data_with_a_number_beyond_a_double_in_a_credential_does_not_decode(client):
    client_data = b'{"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "n": 1e400}'
    status, body = _codec(client, payload=_credential(client_data))

    assert status == 200
    (finding,) = body["findings"]
    assert (finding["code"], finding["offset"], finding["path"], finding["source"]) == (
        "parse-error", 74, '${"n"}', "response.clientDataJSON"
    )


def test_hexadecimal_digits_that_are_also_a_number_beyond_a_double_are_hexadecimal_when_one_item(client):
    # 19 e4 00 is the integer 58368; "19e400" is also 19 times ten to the 400th.
    status, body = _codec(client, payload="19e400")

    assert status == 200
    assert body["data"]["decodedValue"] == 58368
    (finding,) = body["findings"]
    assert (finding["code"], finding["readAs"], finding["alsoValidAs"]) == ("ambiguous-input", "hex", "json")


def test_hexadecimal_digits_that_are_no_item_are_the_number_beyond_a_double(client):
    # 0x99 announces an array of 0xe999 items the input does not have: the digits are the number.
    status, body = _codec(client, payload="99e999")

    assert status == 422
    assert (body["offset"], body["path"]) == (0, "$")

    status, body = _codec(client, payload="99e999", lenient=True)

    assert status == 200
    assert body["data"]["json"] == {"diagnostic": "99e999"}
    assert [(finding["code"], finding.get("readAs")) for finding in body["findings"]] == [
        ("ambiguous-input", "json"),
        ("json-number-out-of-range", None),
    ]
