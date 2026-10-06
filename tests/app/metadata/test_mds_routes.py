"""The MDS routes that only read give a visitor without a namespace none."""

from __future__ import annotations

import base64
import io
import json
from types import SimpleNamespace

import pytest

from server.app import visitor_session
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.routes import mds as mds_routes
from server.app.storage import github_mirror, session_metadata
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.entry_app import entry_app
from tests.app.metadata.upload_entries import minimal_entry


@pytest.fixture(autouse=True)
def _own_namespaces(monkeypatch, tmp_path):
    """This test's own uploads store, so the namespaces listed are only the ones it made."""

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))


_READS = [
    ("GET", "/api/mds/metadata/info", 200),
    ("GET", "/api/mds/metadata/explorer/full", 200),
    ("GET", "/api/mds/metadata/resolve?aaguid=f1d0f1d0-0000-4000-8000-000000000001", 200),
    ("GET", "/api/mds/metadata/custom", 200),
    ("DELETE", "/api/mds/metadata/custom/0123456789abcdef.json", 404),
]


@pytest.mark.parametrize(("method", "path", "status"), _READS)
def test_a_read_mints_no_namespace_and_sets_no_cookie(mds_fixture_snapshot, client, method, path, status):
    response = client.open(path, method=method)

    assert response.status_code == status
    assert response.headers.getlist("Set-Cookie") == []
    assert session_metadata.list_sessions() == []


def test_an_upload_still_mints_the_namespace_it_is_stored_under(mds_fixture_snapshot, client):
    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(json.dumps(minimal_entry("Uploaded")).encode()), "entry.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200, response.get_json()
    assert client.get_cookie("fido.mds.session") is not None
    assert len(session_metadata.list_sessions()) == 1


def test_the_visitors_uploads_are_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/custom")

    assert response.headers["Cache-Control"] == "no-store"
    assert "Cookie" in response.headers["Vary"]


def test_the_full_explorer_is_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 200
    assert len(response.get_json()["entries"]) == 32
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_an_aaguid_no_entry_has_is_not_found(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Metadata entry not found."}


def test_mds_certificate_route_decodes_base64url_without_truncation(monkeypatch):
    """A base64url certificate must decode whole, or be refused -- not truncated."""

    certificate = bytes(range(24, 63))
    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
    )

    urlsafe = base64.urlsafe_b64encode(certificate).decode("ascii").rstrip("=")
    assert "-" in urlsafe or "_" in urlsafe

    with entry_app().test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": urlsafe}
        )

    assert response.status_code == 200
    assert response.get_json() == {
        "details": {"length": 39, "hex": certificate.hex()}
    }
    assert len(certificate) == 39


def test_mds_certificate_route_refuses_plain_text_with_400(monkeypatch):
    monkeypatch.setattr(
        attestation_certificates,
        "serialize_attestation_certificate",
        lambda data: {"length": len(data), "hex": data.hex()},
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/mds/decode-certificate", json={"certificate": PLAIN_TEXT}
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid certificate encoding."}


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
def visitor(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-abc")


@pytest.fixture
def two_entry_upload(monkeypatch, visitor):
    """An upload that expands to two entries, with no GitHub copy and a stand-in snapshot."""

    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda _payload: [{"entry": 1}, {"entry": 2}])
    monkeypatch.setattr(github_mirror, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_effective_full_snapshot", lambda: {"meta": {"entryCount": 1}})


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
