"""JSON input holding NaN, Infinity or -Infinity: not JSON under RFC 8259, which Python's reader accepts.

Read strictly, such text is refused with the offset and path of the first; read
leniently, each is a finding and is shown as the decoder shows a CBOR NaN,
``{"diagnostic": "NaN"}``. The encoder refuses it, pointing at EDN. Every answer
is read here as the browser's ``response.json()`` reads it: strictly.
"""
from __future__ import annotations

import base64
import io
import json

import pytest

from server.app.routes import general

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
    monkeypatch.setattr(general, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general, "expand_metadata_entry_payloads", lambda payload: [payload])
    monkeypatch.setattr(general, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(general, "save_session_metadata_item", lambda payload, original_filename=None: saved.append(payload))
    monkeypatch.setattr(general, "serialize_session_metadata_item", lambda _item: {"storedFilename": "custom.json"})
    monkeypatch.setattr(general, "load_effective_full_snapshot", lambda: {"entries": []})

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
