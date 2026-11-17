"""The MDS routes that only read give a visitor without a namespace none."""

from __future__ import annotations

import base64
import io
import json
from types import SimpleNamespace

import pytest

from server.app import visitor_session
from server.app.config import request_limits
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.routes import assets
from server.app.routes import mds as mds_routes
from server.app.storage import github_mirror, session_metadata
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.entry_app import entry_app
from tests.app.metadata.upload_entries import minimal_entry
from tests.app.storage import fake_github


@pytest.fixture(autouse=True)
def _own_namespaces(own_stores):
    """This test's own stores, so the namespaces listed are only the ones it made."""


_READS = [
    ("GET", "/api/mds/metadata/info", 200),
    ("GET", "/api/mds/metadata/explorer/full", 410),
    ("GET", "/api/mds/metadata/explorer/custom", 200),
    ("GET", "/api/mds/metadata/resolve?aaguid=f1d0f1d0-0000-4000-8000-000000000001", 200),
    ("GET", "/api/mds/metadata/custom", 200),
    ("GET", "/api/mds/metadata/custom/0123456789abcdef.json/icon", 404),
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


def test_a_statement_fido2_cannot_read_is_refused_in_the_answer_not_a_500(mds_fixture_snapshot, client, caplog):
    entry = minimal_entry("Unreadable")
    entry["metadataStatement"]["aaguid"] = 5

    with caplog.at_level("INFO", logger=mds_entries.__name__):
        response = client.post(
            "/api/mds/metadata/upload",
            data={"files": (io.BytesIO(json.dumps(entry).encode()), "unreadable.json")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 400
    assert response.get_json() == {"items": [], "errors": [f"unreadable.json: {mds_entries.UNREADABLE_ENTRY}"]}
    assert [record.levelname for record in caplog.records if record.name == mds_entries.__name__] == ["INFO"]


def test_an_upload_past_the_visitors_quota_saves_and_copies_nothing(mds_fixture_snapshot, make_app, monkeypatch):
    copied = []
    monkeypatch.setattr(
        github_mirror, "queue_uploaded_metadata_files", lambda files: copied.extend(name for name, _data in files)
    )
    client = make_app({request_limits.STORED_METADATA_ENTRIES_KEY: 2}).test_client()
    two = {"entries": [minimal_entry("One"), minimal_entry("Two")]}

    def _upload(*files):
        data = {"files": [(io.BytesIO(json.dumps(content).encode()), name) for name, content in files]}
        return client.post("/api/mds/metadata/upload", data=data, content_type="multipart/form-data")

    assert _upload(("kept.json", minimal_entry("Kept"))).status_code == 200
    response = _upload(("two.json", two), ("broken.json", "not an object"))

    assert response.status_code == 409
    assert response.get_json() == {
        "error": (
            "Nothing was saved: these 2 metadata entries would take this browser's uploads past the 2 metadata "
            "entries this server keeps for one visitor. Delete uploads you no longer use and try again."
        )
    }
    assert [item["source"]["originalFilename"] for item in client.get("/api/mds/metadata/custom").get_json()["items"]] == [
        "kept.json"
    ]
    assert copied == ["kept.json"]


PNG = b"\x89PNG\r\n\x1a\n" + b"uploaded icon" * 4
PNG_ICON = f"data:image/png;base64,{base64.b64encode(PNG).decode()}"


def _uploaded(client, icon=None) -> str:
    """Upload a statement with ``icon`` as this client's visitor: the name it is stored under."""

    entry = minimal_entry("Uploaded")
    if icon is not None:
        entry["metadataStatement"]["icon"] = icon
    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(json.dumps(entry).encode()), "entry.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()["items"][0]["source"]["storedFilename"]


def test_an_uploads_icon_is_its_image_sandboxed_and_kept_for_good(client):
    stored = _uploaded(client, PNG_ICON)

    response = client.get(f"/api/mds/metadata/custom/{stored}/icon")

    assert response.status_code == 200
    assert (response.data, response.mimetype) == (PNG, "image/png")
    assert response.headers["Cache-Control"] == "private, max-age=31536000, immutable"
    assert response.headers["Content-Security-Policy"] == assets.ICON_POLICY
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_an_uploads_icon_is_served_to_its_visitor_alone(app, client):
    stored = _uploaded(client, PNG_ICON)
    other = app.test_client()

    assert other.get(f"/api/mds/metadata/custom/{stored}/icon").status_code == 404
    _uploaded(other, PNG_ICON)
    assert other.get(f"/api/mds/metadata/custom/{stored}/icon").status_code == 404


@pytest.mark.parametrize(
    ("icon", "name"),
    [
        (None, "{stored}"),
        ("data:image/bmp;base64,Qk0=", "{stored}"),
        (PNG_ICON, "{stored}.meta.json"),
        (PNG_ICON, "missing.json"),
        (PNG_ICON, ".{stored}"),
    ],
    ids=["no-icon", "no-file-is-made-of-it", "the-info-file", "missing", "hidden"],
)
def test_no_icon_is_served_but_the_image_of_an_upload(client, icon, name):
    stored = _uploaded(client, icon)

    assert client.get(f"/api/mds/metadata/custom/{name.format(stored=stored)}/icon").status_code == 404


def test_an_uploaded_file_nested_too_deep_is_refused_and_nothing_is_saved(mds_fixture_snapshot, client):
    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(b"[" * 100_000 + b"]" * 100_000), "deep.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "items": [],
        "errors": ["deep.json: JSON nested more than 64 deep, deeper than this server reads"],
    }


def test_the_visitors_uploads_are_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/custom")

    assert response.headers["Cache-Control"] == "no-store"
    assert "Cookie" in response.headers["Vary"]


def test_the_visitors_explorer_rows_are_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/explorer/custom")

    assert response.status_code == 200
    assert response.get_json() == {
        "meta": {"entryCount": 32, "baseEntryCount": 32, "customEntryCount": 0, "hasCustomEntries": False},
        "entries": [],
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_without_a_snapshot_the_visitors_explorer_rows_are_answered_all_the_same(client):
    response = client.get("/api/mds/metadata/explorer/custom")

    assert response.status_code == 200
    assert response.get_json()["meta"]["baseEntryCount"] == 0


def test_a_page_older_than_the_server_is_told_to_reload_it(client):
    response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 410
    assert response.get_json() == {"error": "This page is older than the server: reload it."}
    assert response.headers["Cache-Control"] == "no-store"


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
    """An upload that expands to two entries, with no GitHub copy and stand-in rows for the session."""

    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda _payload: [{"entry": 1}, {"entry": 2}])
    monkeypatch.setattr(github_mirror, "queue_uploaded_metadata_files", lambda _files: None)
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_custom_entries", lambda: {"meta": {"customEntryCount": 1}, "entries": []})


@pytest.mark.parametrize(
    ("request_kwargs", "status", "answer"),
    [
        ({"data": "payload", "content_type": "text/plain"}, 400, {"error": "Expected JSON payload."}),
        ({"json": {}}, 400, {"error": "Certificate is required."}),
        ({"json": {"certificate": "💥"}}, 400, {"error": "Invalid certificate encoding."}),
        (
            {"json": {"certificate": base64.b64encode(b"bad-cert").decode("ascii")}},
            422,
            {"error": "Unable to decode certificate."},
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
        ((_Storage("bad.json", exc=RuntimeError("disk read failed")),), "Failed to read bad.json."),
        ((_Storage("utf8.json", b"\xff"),), "utf8.json is not valid UTF-8 JSON."),
        ((_Storage("array.json", b"[]"),), "array.json must contain a JSON object."),
    ],
    ids=["no-files", "not-json-name", "unreadable", "not-utf8", "not-an-object"],
)
def test_an_upload_without_a_usable_json_object_is_refused_with_the_reason(monkeypatch, visitor, files, error):
    response, status = _upload(monkeypatch, *files)

    assert status == 400
    assert response.get_json() == {"items": [], "errors": [error]}


def test_an_upload_that_is_not_json_is_refused_naming_the_file_and_where(monkeypatch, visitor):
    response, status = _upload(monkeypatch, _Storage("syntax.json", b"{\n  not-json"))

    assert status == 400
    assert response.get_json() == {"items": [], "errors": ["syntax.json is not JSON (line 2, column 3)."]}


@pytest.mark.parametrize(
    ("raised", "error"),
    [
        (mds_entries.MetadataRefused("Metadata JSON does not contain any entries."), "expand.json: Metadata JSON does not contain any entries."),
        (ValueError("a reader's own words"), f"expand.json: {mds_entries.UNREADABLE_ENTRY}"),
        (TypeError("a reader's own words"), f"expand.json: {mds_entries.UNREADABLE_ENTRY}"),
    ],
    ids=["refused", "value-error", "type-error"],
)
def test_an_upload_whose_entries_do_not_read_is_refused_with_its_own_sentence_only(monkeypatch, visitor, raised, error):
    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda _payload: (_ for _ in ()).throw(raised))

    response, status = _upload(monkeypatch, _Storage("expand.json", b"{}"))

    assert status == 400
    assert response.get_json() == {"items": [], "errors": [error]}


@pytest.mark.parametrize(
    ("raised", "error"),
    [
        (mds_entries.MetadataRefused("duplicate entry"), "mixed.json (entry 1): duplicate entry"),
        (ValueError("a store's own words"), f"mixed.json (entry 1): {mds_entries.UNREADABLE_ENTRY}"),
    ],
    ids=["refused", "value-error"],
)
def test_an_upload_keeps_the_entries_it_can_save_and_names_the_others(monkeypatch, two_entry_upload, raised, error):
    def _save_item(entry_payload, original_filename=None):
        if entry_payload.get("entry") == 1:
            raise raised
        return {"storedFilename": "stored-2.json", "originalFilename": original_filename}

    monkeypatch.setattr(mds_uploads, "save_session_metadata_item", _save_item)

    response, status = _upload(monkeypatch, _Storage("mixed.json", b"{}"))

    payload = response.get_json()
    assert status == 200
    assert payload["items"] == [{"storedFilename": "stored-2.json", "originalFilename": "mixed.json (entry 2)"}]
    assert payload["errors"] == [error]
    assert payload["custom"] == {"meta": {"customEntryCount": 1}, "entries": []}
    assert "snapshot" not in payload


def test_an_upload_the_store_cannot_save_answers_500(monkeypatch, two_entry_upload):
    monkeypatch.setattr(
        mds_uploads,
        "save_session_metadata_item",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("persistence down")),
    )

    response, status = _upload(monkeypatch, _Storage("fatal.json", b"{}"))

    assert status == 500
    assert response.get_json() == {"error": "Failed to store uploaded metadata on the server."}


def test_an_upload_without_a_file_name_is_named_metadata_json(monkeypatch, visitor):
    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda payload: [payload])
    monkeypatch.setattr(github_mirror, "queue_uploaded_metadata_files", lambda _files: None)
    monkeypatch.setattr(
        mds_uploads,
        "save_session_metadata_item",
        lambda _payload, original_filename=None: {"originalFilename": original_filename},
    )
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_custom_entries", lambda: {"meta": {"customEntryCount": 1}, "entries": []})

    response, status = _upload(monkeypatch, _Storage("   ", b"{}"))

    assert status == 200
    assert response.get_json()["items"] == [{"originalFilename": "metadata.json"}]


@pytest.mark.parametrize(
    ("delete", "status", "answer"),
    [
        (lambda _name: (_ for _ in ()).throw(ValueError("invalid filename")), 400, {"error": "Invalid metadata filename."}),
        (
            lambda _name: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
            500,
            {"error": "Failed to delete the uploaded metadata file."},
        ),
        (lambda _name: False, 404, {"deleted": False, "message": "Metadata entry not found."}),
    ],
    ids=["invalid-name", "store-fails", "not-found"],
)
def test_deleting_an_upload_answers_by_what_the_store_says(monkeypatch, visitor, delete, status, answer):
    monkeypatch.setattr(mds_uploads, "delete_session_metadata_item", delete)

    response = entry_app().test_client().delete("/api/mds/metadata/custom/invalid")

    assert response.status_code == status
    assert response.get_json() == answer


def test_a_file_is_queued_for_the_device_log_only_once_one_of_its_entries_saved(monkeypatch, visitor):
    queued = []
    monkeypatch.setattr(github_mirror, "queue_uploaded_metadata_files", lambda files: queued.append(list(files)))
    monkeypatch.setattr(mds_entries, "expand_metadata_entry_payloads", lambda payload: [payload])

    def _save_item(entry_payload, original_filename=None):
        if entry_payload.get("refuse"):
            raise mds_entries.MetadataRefused("not kept")
        return {"storedFilename": "stored.json", "originalFilename": original_filename}

    monkeypatch.setattr(mds_uploads, "save_session_metadata_item", _save_item)
    monkeypatch.setattr(mds_uploads, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(mds_effective, "load_custom_entries", lambda: {"meta": {"customEntryCount": 1}, "entries": []})

    response, status = _upload(
        monkeypatch, _Storage("refused.json", b'{"refuse": true}'), _Storage("kept.json", b'{"keep": true}')
    )

    assert status == 200, response.get_json()
    assert queued == [[("kept.json", b'{"keep": true}')]]


def test_an_upload_the_store_cannot_save_queues_nothing_for_the_device_log(monkeypatch, two_entry_upload):
    queued = []
    monkeypatch.setattr(github_mirror, "queue_uploaded_metadata_files", lambda files: queued.append(list(files)))
    monkeypatch.setattr(
        mds_uploads,
        "save_session_metadata_item",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("persistence down")),
    )

    _response, status = _upload(monkeypatch, _Storage("fatal.json", b"{}"))

    assert status == 500
    assert queued == []


def test_an_uploaded_file_reaches_the_device_log_once_saved(mds_fixture_snapshot, client, monkeypatch, tmp_path):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(tmp_path / "outbox"))
    kept = json.dumps(minimal_entry("Kept")).encode()
    unreadable = minimal_entry("Unreadable")
    unreadable["metadataStatement"]["aaguid"] = 5

    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": [(io.BytesIO(kept), "kept.json"), (io.BytesIO(json.dumps(unreadable).encode()), "unreadable.json")]},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200, response.get_json()
    assert github.files == {"metadata/kept.json": kept}
