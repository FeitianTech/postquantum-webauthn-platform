"""JSON input holding NaN, Infinity or -Infinity: not JSON under RFC 8259, which Python's reader accepts.

Each answer is read here as text, as the browser's ``response.json()`` reads it.
"""
from __future__ import annotations

import base64
import io
import json
import math

import pytest

from server.app.routes import general

_CONSTANTS = '{"a": NaN, "b": [Infinity, -Infinity]}'


def _codec(client, **body):
    return client.post("/api/codec", json=body)


def test_decoding_json_with_nan_answers_it_bare(client):
    response = _codec(client, payload=_CONSTANTS)

    assert response.status_code == 200
    assert '"json":{"a":NaN,"b":[Infinity,-Infinity]}' in response.get_data(as_text=True)


@pytest.mark.parametrize(("target", "echoed"), [("CBOR", '"decodedValue":{"a":NaN'), ("JSON", '"json":{"a":NaN')])
def test_encoding_json_with_nan_answers_it_bare(client, target, echoed):
    response = _codec(client, payload=_CONSTANTS, mode="encode", format=target)

    assert response.status_code == 200
    assert echoed in response.get_data(as_text=True)


def test_client_data_with_nan_in_a_credential_is_read_without_a_word(client):
    client_data = b'{"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "n": NaN}'
    credential = {
        "id": "AAAA",
        "type": "public-key",
        "response": {"clientDataJSON": base64.urlsafe_b64encode(client_data).decode().rstrip("=")},
    }

    response = _codec(client, payload=json.dumps(credential))

    assert response.status_code == 200
    assert response.get_json()["findings"] == []


def test_an_uploaded_metadata_file_with_nan_is_accepted(client, monkeypatch):
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

    assert response.status_code == 200
    assert math.isnan(saved[0]["metadataStatement"]["n"])
