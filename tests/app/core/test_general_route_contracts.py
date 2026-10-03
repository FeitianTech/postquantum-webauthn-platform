import base64
from types import SimpleNamespace

import pytest

from server.app import visitor_session
from server.app.decoder.decode import text as decode_text
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.routes import mds as mds_routes
from server.app.storage import github_mirror
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app


class _Files:
    def __init__(self, entries):
        self._entries = list(entries)

    def getlist(self, name):
        assert name == "files"
        return list(self._entries)


class _Storage:
    def __init__(self, filename, data=None, exc=None):
        self.filename = filename
        self._data = data
        self._exc = exc

    def read(self):
        if self._exc is not None:
            raise self._exc
        return self._data


def _upload(monkeypatch, *files):
    """Call the upload route with ``files`` as the request's files; its response and status."""

    monkeypatch.setattr(mds_routes, "request", SimpleNamespace(files=_Files(files) if files else None))
    with entry_app().app_context():
        result = mds_routes.api_upload_custom_metadata()
    if isinstance(result, tuple):
        return result
    return result, result.status_code


@pytest.fixture
def fake_decoders(monkeypatch):
    """A codec decoder and certificate reader whose failures the payload chooses."""

    def _fake_decode(payload_text, **_options):
        if payload_text == "bad":
            raise ValueError("bad payload")
        if payload_text == "boom":
            raise RuntimeError("decoder crashed")
        return {"success": True, "decoded": payload_text}

    def _fake_serialize(certificate_bytes):
        if certificate_bytes == b"bad-cert":
            raise ValueError("certificate parse failed")
        return {"length": len(certificate_bytes), "hex": certificate_bytes.hex()}

    monkeypatch.setattr(decode_text, "decode_payload_text", _fake_decode)
    monkeypatch.setattr(attestation_certificates, "serialize_attestation_certificate", _fake_serialize)


@pytest.fixture
def visitor(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-abc")


@pytest.mark.parametrize(
    ("request_kwargs", "status", "answer"),
    [
        ({"data": "payload", "content_type": "text/plain"}, 400, {"error": "Expected JSON payload."}),
        ({"json": {"payload": "   "}}, 400, {"error": "Codec payload must be a non-empty string."}),
        ({"json": {"payload": "bad"}}, 422, {"error": "bad payload"}),
        ({"json": {"payload": "boom"}}, 500, {"error": "Unable to decode payload."}),
        ({"json": {"payload": "AQID"}}, 200, {"success": True, "decoded": "AQID"}),
    ],
    ids=["not-json", "empty", "unreadable", "decoder-fails", "decoded"],
)
def test_the_codec_route_answers_each_payload_with_its_status(fake_decoders, request_kwargs, status, answer):
    response = entry_app().test_client().post("/api/codec", **request_kwargs)

    assert response.status_code == status
    assert response.get_json() == answer


@pytest.mark.parametrize(
    ("request_kwargs", "status", "answer"),
    [
        ({"data": "payload", "content_type": "text/plain"}, 400, {"error": "Expected JSON payload."}),
        ({"json": {}}, 400, {"error": "Certificate is required."}),
        ({"json": {"certificate": "💥"}}, 400, {"error": "Invalid certificate encoding."}),
        (
            {"json": {"certificate": base64.b64encode(b"bad-cert").decode("ascii")}},
            422,
            {"error": "Unable to decode certificate: certificate parse failed"},
        ),
        (
            {"json": {"certificate": f"  {base64.b64encode(b'good-cert').decode('ascii').rstrip('=')}  \n"}},
            200,
            {"details": {"length": len(b"good-cert"), "hex": b"good-cert".hex()}},
        ),
    ],
    ids=["not-json", "missing", "bad-encoding", "unparsable", "trimmed-and-padded"],
)
def test_the_certificate_route_answers_each_certificate_with_its_status(fake_decoders, request_kwargs, status, answer):
    response = entry_app().test_client().post("/api/mds/decode-certificate", **request_kwargs)

    assert response.status_code == status
    assert response.get_json() == answer


def test_the_custom_metadata_list_answers_the_visitors_uploads(monkeypatch):
    monkeypatch.setattr(mds_uploads, "list_session_metadata_items", lambda: [{"storedFilename": "one.json"}])
    monkeypatch.setattr(
        mds_uploads,
        "serialize_session_metadata_item",
        lambda item: {"storedFilename": item["storedFilename"], "label": "demo"},
    )

    response = entry_app().test_client().get("/api/mds/metadata/custom")

    assert response.status_code == 200
    assert response.get_json() == {"items": [{"storedFilename": "one.json", "label": "demo"}]}


@pytest.mark.parametrize(
    ("files", "error"),
    [
        ((), "No JSON files were provided."),
        ((_Storage("note.txt", b"{}"),), "note.txt is not a JSON file."),
        ((_Storage("bad.json", exc=RuntimeError("disk read failed")),), "Failed to read bad.json: disk read failed"),
        ((_Storage("utf8.json", b"\xff"),), "utf8.json is not valid UTF-8 JSON."),
        ((_Storage("array.json", b"[]"),), "array.json must contain a JSON object."),
    ],
    ids=["no-files", "not-json-name", "unreadable", "not-utf8", "not-an-object"],
)
def test_an_upload_without_a_usable_json_object_is_refused_with_the_reason(monkeypatch, visitor, files, error):
    response, status = _upload(monkeypatch, *files)

    assert status == 400
    assert response.get_json() == {"items": [], "errors": [error]}


def test_an_upload_that_is_not_json_is_refused_naming_the_file(monkeypatch, visitor):
    response, status = _upload(monkeypatch, _Storage("syntax.json", b"{not-json"))

    assert status == 400
    assert response.get_json()["items"] == []
    assert "syntax.json:" in response.get_json()["errors"][0]


def test_an_upload_whose_entries_do_not_read_is_refused_with_the_reason(monkeypatch, visitor):
    monkeypatch.setattr(
        mds_entries,
        "expand_metadata_entry_payloads",
        lambda _payload: (_ for _ in ()).throw(ValueError("bad metadata object")),
    )

    response, status = _upload(monkeypatch, _Storage("expand.json", b"{}"))

    assert status == 400
    assert response.get_json() == {"items": [], "errors": ["expand.json: bad metadata object"]}


@pytest.fixture
def two_entry_upload(monkeypatch, visitor):
    """An upload that expands to two entries, with no GitHub copy and a stand-in snapshot."""

    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda _payload: [{"entry": 1}, {"entry": 2}])
    monkeypatch.setattr(github_mirror, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_effective_full_snapshot", lambda: {"meta": {"entryCount": 1}})


def test_an_upload_keeps_the_entries_it_can_save_and_names_the_others(monkeypatch, two_entry_upload):
    def _save_item(entry_payload, original_filename=None):
        if entry_payload.get("entry") == 1:
            raise ValueError("duplicate entry")
        return {"storedFilename": "stored-2.json", "originalFilename": original_filename}

    monkeypatch.setattr(mds_uploads, "save_session_metadata_item", _save_item)

    response, status = _upload(monkeypatch, _Storage("mixed.json", b"{}"))

    payload = response.get_json()
    assert status == 200
    assert payload["items"] == [{"storedFilename": "stored-2.json", "originalFilename": "mixed.json (entry 2)"}]
    assert payload["errors"] == ["mixed.json (entry 1): duplicate entry"]
    assert payload["snapshot"] == {"meta": {"entryCount": 1}}


def test_an_upload_the_store_cannot_save_answers_500(monkeypatch, two_entry_upload):
    monkeypatch.setattr(
        mds_uploads,
        "save_session_metadata_item",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("persistence down")),
    )

    response, status = _upload(monkeypatch, _Storage("fatal.json", b"{}"))

    assert status == 500
    assert response.get_json() == {"error": "persistence down"}


def test_an_upload_without_a_file_name_is_named_metadata_json(monkeypatch, visitor):
    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda payload: [payload])
    monkeypatch.setattr(github_mirror, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        mds_uploads,
        "save_session_metadata_item",
        lambda _payload, original_filename=None: {"originalFilename": original_filename},
    )
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_effective_full_snapshot", lambda: {"meta": {"entryCount": 1}})

    response, status = _upload(monkeypatch, _Storage("   ", b"{}"))

    assert status == 200
    assert response.get_json()["items"] == [{"originalFilename": "metadata.json"}]


@pytest.mark.parametrize(
    ("delete", "status", "answer"),
    [
        (lambda _name: (_ for _ in ()).throw(ValueError("invalid filename")), 400, {"error": "invalid filename"}),
        (lambda _name: (_ for _ in ()).throw(RuntimeError("storage unavailable")), 500, {"error": "storage unavailable"}),
        (lambda _name: False, 404, {"deleted": False, "message": "Metadata entry not found."}),
    ],
    ids=["invalid-name", "store-fails", "not-found"],
)
def test_deleting_an_upload_answers_by_what_the_store_says(monkeypatch, visitor, delete, status, answer):
    monkeypatch.setattr(mds_uploads, "delete_session_metadata_item", delete)

    response = entry_app().test_client().delete("/api/mds/metadata/custom/invalid")

    assert response.status_code == status
    assert response.get_json() == answer


def test_without_a_snapshot_the_full_explorer_is_not_available(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(mds_effective, "load_effective_full_snapshot", lambda: {})

    response = entry_app().test_client().get("/api/mds/metadata/explorer/full")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Verified metadata snapshot is not available."}
