from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from flask import ctx, g, session


@pytest.fixture
def metadata_module(monkeypatch):
    module = pytest.importorskip("server.app.metadata")

    monkeypatch.setattr(module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_source", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_trust_verified", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_entry_ids", set(), raising=False)
    monkeypatch.setattr(module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_explorer_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_session_metadata_entry_ids", set(), raising=False)

    return module


def _minimal_entry_payload(*, aaguid: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") -> dict:
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": "Demo",
            "authenticatorVersion": 1,
            "schema": 3,
            "upv": [],
            "attestationTypes": [],
            "userVerificationDetails": [],
            "keyProtection": [],
            "matcherProtection": [],
            "attachmentHint": [],
            "tcDisplay": [],
            "attestationRootCertificates": [],
        },
    }


def test_session_cookie_scheduler_branches_and_after_request_cookie(metadata_module, monkeypatch):
    config = pytest.importorskip("server.app.config")

    touched = []
    monkeypatch.setattr(
        metadata_module,
        "_note_session_activity",
        lambda session_id, **_kwargs: touched.append(session_id),
        raising=False,
    )

    metadata_module._schedule_session_cookie("outside-context")

    with config.app.test_request_context("/", base_url="https://localhost"):
        metadata_module._schedule_session_cookie("   ")
        request_ctx = ctx._cv_request.get()
        assert request_ctx._after_request_functions == []

        metadata_module._schedule_session_cookie("session-cookie")
        assert g._session_metadata_cookie == "session-cookie"
        assert len(request_ctx._after_request_functions) == 1

        metadata_module._schedule_session_cookie("session-cookie")
        assert len(request_ctx._after_request_functions) == 1

        response = request_ctx._after_request_functions[0](config.app.response_class("ok"))
        set_cookie = response.headers["Set-Cookie"]
        assert f"{metadata_module._SESSION_METADATA_COOKIE_NAME}=session-cookie" in set_cookie
        assert "Secure" in set_cookie
        assert "SameSite=None" in set_cookie

    assert touched == ["session-cookie", "session-cookie"]


def test_get_session_id_and_ensure_paths_cover_invalid_existing_and_error_branch(
    metadata_module, monkeypatch
):
    config = pytest.importorskip("server.app.config")

    assert metadata_module._get_metadata_session_id(create=True) is None

    scheduled = []
    monkeypatch.setattr(
        metadata_module,
        "_schedule_session_cookie",
        lambda identifier: scheduled.append(identifier),
        raising=False,
    )
    monkeypatch.setattr(metadata_module.secrets, "token_urlsafe", lambda _n: "generated-session")

    with config.app.test_request_context(
        "/",
        headers={"Cookie": f"{metadata_module._SESSION_METADATA_COOKIE_NAME}=cookie-session"},
    ):
        session[metadata_module._SESSION_METADATA_SESSION_KEY] = ".invalid"
        assert metadata_module._get_metadata_session_id(create=False) == "cookie-session"
        assert session[metadata_module._SESSION_METADATA_SESSION_KEY] == "cookie-session"

    with config.app.test_request_context("/"):
        session[metadata_module._SESSION_METADATA_SESSION_KEY] = ".invalid"
        assert metadata_module._get_metadata_session_id(create=False) is None
        assert metadata_module._get_metadata_session_id(create=True) == "generated-session"

    with config.app.test_request_context("/"):
        monkeypatch.setattr(metadata_module, "_get_metadata_session_id", lambda **_kwargs: None, raising=False)
        with pytest.raises(RuntimeError, match="Unable to establish"):
            metadata_module.ensure_metadata_session_id()

    with config.app.test_request_context("/"):
        monkeypatch.setattr(
            metadata_module,
            "_get_metadata_session_id",
            lambda **_kwargs: "ensured-session",
            raising=False,
        )
        assert metadata_module.ensure_metadata_session_id() == "ensured-session"
        assert session.permanent is True

    assert scheduled == ["cookie-session", "generated-session"]


def test_session_directory_touch_and_resolve_error_paths(metadata_module, monkeypatch):
    schedule_calls = []
    monkeypatch.setattr(
        metadata_module,
        "_schedule_inactive_session_cleanup",
        lambda: schedule_calls.append(True),
        raising=False,
    )

    assert metadata_module._session_metadata_directory("", create=False) is None
    assert metadata_module._session_metadata_directory("../escape", create=False) is None

    errors = []
    monkeypatch.setattr(
        metadata_module.app.logger,
        "error",
        lambda *args, **kwargs: errors.append((args, kwargs)),
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "ensure_session",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("ensure failed")),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="ensure failed"):
        metadata_module._session_metadata_directory("session-a", create=True)

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "ensure_session",
        lambda _sid: None,
        raising=False,
    )
    assert (
        metadata_module._session_metadata_directory("session-a", create=True, cleanup=False)
        == "session-a"
    )
    assert metadata_module._session_metadata_directory("session-a", create=False, cleanup=True) == "session-a"

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "touch_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("touch failed")),
        raising=False,
    )
    metadata_module._touch_session_last_access("session-a")

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "resolve_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("resolve failed")),
        raising=False,
    )
    assert metadata_module._resolve_session_last_access("session-a") is None

    assert errors
    assert schedule_calls == [True]


def test_env_interval_upload_and_normalisation_error_edges(metadata_module, monkeypatch):
    monkeypatch.setenv("TEST_ENV_BOOL", " YES ")
    assert metadata_module._env_flag("TEST_ENV_BOOL") is True

    warnings = []
    monkeypatch.setattr(
        metadata_module.app.logger,
        "warning",
        lambda *args, **kwargs: warnings.append((args, kwargs)),
        raising=False,
    )
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "bad-seconds")
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV, "bad-hours")

    assert metadata_module._resolve_cleanup_interval() == timedelta(hours=6)
    assert len(warnings) >= 2

    uploads = []
    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: True, raising=False)
    monkeypatch.setattr(metadata_module, "git_blob_sha", lambda _content: "new-sha", raising=False)
    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda _folder: [
            123,
            {"type": "dir", "name": "not-a-file"},
            {"type": "file", "name": "target.json", "sha": "old-sha", "path": 99},
        ],
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "github_upload_file",
        lambda *args, **kwargs: uploads.append((args, kwargs)),
        raising=False,
    )

    assert metadata_module.maybe_store_uploaded_metadata_file("target.json", b"{}") is True
    assert uploads[0][0][0] == "metadata/target.json"
    assert uploads[0][1] == {"sha": "old-sha"}


def test_build_expand_extract_and_merge_error_branches(metadata_module, monkeypatch):
    entry, _, payload = metadata_module.build_metadata_entry_components(
        {
            "timeOfLastStatusChange": "   ",
            "attestationCertificateKeyIdentifiers": ["   ", 42],
            "aaid": " id#1 ",
            "aaguid": "   ",
            "metadataStatement": {
                "description": "Demo",
                "authenticatorVersion": 1,
                "schema": 3,
                "upv": [],
                "attestationTypes": [],
                "userVerificationDetails": [],
                "keyProtection": [],
                "matcherProtection": [],
                "attachmentHint": [],
                "tcDisplay": [],
                "attestationRootCertificates": [],
            },
        }
    )
    assert payload["aaid"] == "id#1"
    assert "aaguid" not in payload
    assert "attestationCertificateKeyIdentifiers" not in payload
    assert payload["timeOfLastStatusChange"]
    assert entry["metadataStatement"]["description"] == "Demo"

    with pytest.raises(TypeError, match="must be an object"):
        metadata_module.expand_metadata_entry_payloads("not-a-mapping")

    monkeypatch.setattr(metadata_module, "_clone_json_value", lambda _value: None, raising=False)
    with pytest.raises(ValueError, match="could not be cloned"):
        metadata_module.expand_metadata_entry_payloads({"entries": [{"metadataStatement": {"description": "x"}}]})

    assert metadata_module._normalise_aaguid(123) is None

    class _NoMappingEntry:
        aaguid = None
        metadata_statement = None
        metadataStatement = "not-a-mapping"

    assert metadata_module._extract_entry_aaguid(_NoMappingEntry()) is None

    session_entry_one = metadata_module.MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())
    session_entry_two = metadata_module.MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())

    item_one = metadata_module.SessionMetadataItem(
        filename="one.json",
        payload=_minimal_entry_payload(),
        legal_header=None,
        entry=session_entry_one,
        uploaded_at="2026-04-04T00:00:00+00:00",
        original_filename="one.json",
        mtime=1.0,
    )
    item_two = metadata_module.SessionMetadataItem(
        filename="two.json",
        payload=_minimal_entry_payload(),
        legal_header="Session Legal",
        entry=session_entry_two,
        uploaded_at="2026-04-04T00:00:00+00:00",
        original_filename="two.json",
        mtime=2.0,
    )

    monkeypatch.setattr(
        metadata_module,
        "_extract_entry_aaguid",
        lambda value: metadata_module._normalise_aaguid(str(getattr(value, "aaguid", ""))),
        raising=False,
    )

    merged = metadata_module._merge_metadata(None, [item_one, item_two])
    assert merged.legal_header == "Session Legal"
    assert len(merged.entries) == 1


class _NotJSONSerializable:
    pass


def test_save_list_delete_serialize_and_datetime_edge_paths(metadata_module, monkeypatch):
    monkeypatch.setattr(metadata_module, "ensure_metadata_session_id", lambda: "session-a", raising=False)
    monkeypatch.setattr(metadata_module, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a", raising=False)
    monkeypatch.setattr(
        metadata_module,
        "build_metadata_entry_components",
        lambda _raw: (
            metadata_module.MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload()),
            None,
            {"metadataStatement": {"description": "x"}},
        ),
        raising=False,
    )

    with pytest.raises(ValueError, match="unsupported types"):
        metadata_module.save_session_metadata_item({"bad": _NotJSONSerializable()})

    monkeypatch.setattr(metadata_module, "_get_metadata_session_id", lambda **_kwargs: "session-a", raising=False)
    monkeypatch.setattr(metadata_module, "_session_metadata_directory", lambda *_args, **_kwargs: None, raising=False)
    assert metadata_module.list_session_metadata_items() == []

    monkeypatch.setattr(metadata_module, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a", raising=False)
    monkeypatch.setattr(metadata_module, "_note_session_activity", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "list_files",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("list failed")),
        raising=False,
    )
    assert metadata_module.list_session_metadata_items() == []

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "list_files",
        lambda _sid: ["entry.json"],
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "read_file",
        lambda _sid, _name: json.dumps(_minimal_entry_payload()).encode("utf-8"),
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "_load_session_metadata_info",
        lambda _sid, _name: {
            "uploaded_at": " 2026-04-04T00:00:00+00:00 ",
            "original_filename": " original.json ",
        },
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "file_mtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("mtime failed")),
        raising=False,
    )

    listed = metadata_module.list_session_metadata_items("session-a")
    assert len(listed) == 1
    assert listed[0].mtime is None
    assert listed[0].uploaded_at == "2026-04-04T00:00:00+00:00"
    assert listed[0].original_filename == "original.json"

    monkeypatch.setattr(metadata_module, "_session_metadata_directory", lambda *_args, **_kwargs: None, raising=False)
    assert metadata_module.delete_session_metadata_item("entry.json", session_id="session-a") is False

    monkeypatch.setattr(metadata_module, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a", raising=False)
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "file_exists",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("exists failed")),
        raising=False,
    )
    assert metadata_module.delete_session_metadata_item("entry.json", session_id="session-a") is False

    delete_calls = []

    def _delete_file(_sid, name, *, missing_ok=True):
        delete_calls.append((name, missing_ok))
        if name.endswith(metadata_module._SESSION_METADATA_INFO_SUFFIX):
            raise OSError("info delete ignored")

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "file_exists",
        lambda *_args, **_kwargs: True,
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "delete_file",
        _delete_file,
        raising=False,
    )
    monkeypatch.setattr(metadata_module, "_prune_session_metadata_directory", lambda *_args, **_kwargs: None, raising=False)

    assert metadata_module.delete_session_metadata_item("entry.json", session_id="session-a") is True
    assert delete_calls[0] == ("entry.json", False)
    assert delete_calls[1] == ("entry.json.meta.json", True)

    serialized = metadata_module.serialize_session_metadata_item(
        metadata_module.SessionMetadataItem(
            filename="stored.json",
            payload={"metadataStatement": {"description": "Demo"}},
            legal_header="Legal Header",
            entry=metadata_module.MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload()),
            uploaded_at=None,
            original_filename=None,
            mtime=None,
        )
    )
    assert serialized["source"] == {"storedFilename": "stored.json"}
    assert serialized["legalHeader"] == "Legal Header"

    error = metadata_module.MetadataDownloadError("boom", status_code=503, retry_after="60")
    assert error.status_code == 503
    assert error.retry_after == "60"

    assert metadata_module._parse_http_datetime(None) is None
    monkeypatch.setattr(metadata_module, "parsedate_to_datetime", lambda _value: datetime(2026, 1, 1, 0, 0, 0), raising=False)
    parsed = metadata_module._parse_http_datetime("Wed, 01 Jan 2026 00:00:00 GMT")
    assert parsed is not None and parsed.tzinfo is not None

    assert metadata_module._format_last_modified(None) is None
    assert metadata_module.format_last_modified_header("Thu, 01 Jan 1970 00:00:00 GMT") == "2026-01-01T00:00:00+00:00"


def test_cache_and_bootstrap_fallback_helpers(metadata_module, monkeypatch, tmp_path):
    cache_path = tmp_path / "cache" / "metadata-cache.json"
    monkeypatch.setattr(metadata_module, "MDS_METADATA_CACHE_PATH", str(cache_path), raising=False)

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("[]", encoding="utf-8")
    assert metadata_module.load_metadata_cache_entry() == {}

    cache_path.write_text(
        json.dumps(
            {
                "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                "last_modified_iso": "  ",
                "etag": " etag-value ",
                "fetched_at": " 2026-04-04T00:00:00+00:00 ",
            }
        ),
        encoding="utf-8",
    )
    loaded_cache = metadata_module.load_metadata_cache_entry()
    assert loaded_cache["last_modified_iso"] == "2015-10-21T07:28:00+00:00"
    assert loaded_cache["etag"] == "etag-value"

    monkeypatch.setattr(
        metadata_module.os,
        "makedirs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("mkdir failed")),
        raising=False,
    )
    metadata_module._store_metadata_cache_entry(
        last_modified_header="x",
        last_modified_iso="y",
        etag="z",
    )

    wrapper_calls = []
    monkeypatch.setattr(
        metadata_module,
        "_store_metadata_cache_entry",
        lambda **kwargs: wrapper_calls.append(kwargs),
        raising=False,
    )
    metadata_module.store_metadata_cache_entry(
        last_modified_header="a",
        last_modified_iso="b",
        etag="c",
    )
    assert wrapper_calls == [
        {
            "last_modified_header": "a",
            "last_modified_iso": "b",
            "etag": "c",
        }
    ]

    real_load_base_metadata = metadata_module._load_base_metadata

    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (None, None), raising=False)
    assert metadata_module.load_cached_metadata_snapshot() is False
    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (object(), None), raising=False)
    assert metadata_module.load_cached_metadata_snapshot() is True

    monkeypatch.setattr(metadata_module, "_load_base_metadata", real_load_base_metadata, raising=False)

    monkeypatch.setattr(
        metadata_module.os.path,
        "getmtime",
        lambda _path: (_ for _ in ()).throw(OSError("mtime missing")),
        raising=False,
    )
    monkeypatch.setattr(metadata_module, "_load_verified_metadata_fallback", lambda: (None, None), raising=False)
    metadata_value, marker = metadata_module._load_base_metadata()
    assert metadata_value is None and marker is None
    assert metadata_module._base_metadata_source is None
    assert metadata_module._base_metadata_trust_verified is None

    verified_path = tmp_path / "verified.json"
    monkeypatch.setattr(metadata_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)

    missing_loaded, _ = metadata_module._load_verified_metadata_fallback()
    assert missing_loaded is None

    verified_path.write_text("{not-json", encoding="utf-8")
    invalid_loaded, _ = metadata_module._load_verified_metadata_fallback()
    assert invalid_loaded is None

    verified_path.write_text("[]", encoding="utf-8")
    assert metadata_module._load_verified_metadata_payload() is None

    verified_payload = {
        "legalHeader": "L",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [],
    }
    verified_path.write_text(json.dumps(verified_payload), encoding="utf-8")

    monkeypatch.setattr(metadata_module.os.path, "getmtime", lambda path: 20.0 if path == str(verified_path) else 10.0, raising=False)
    explorer_cache_marker = (10.0, 20.0)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_cache", {"meta": {"entryCount": 9}}, raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_mtime", explorer_cache_marker, raising=False)
    cached_snapshot, cached_marker = metadata_module._load_base_explorer_snapshot()
    assert cached_snapshot == {"meta": {"entryCount": 9}}
    assert cached_marker == explorer_cache_marker

    explorer_path = tmp_path / "explorer.json"
    explorer_path.write_text("{invalid-json", encoding="utf-8")
    monkeypatch.setattr(metadata_module, "MDS_EXPLORER_PATH", str(explorer_path), raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "load_metadata_cache_entry", lambda: {"etag": "x"}, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "build_explorer_snapshot",
        lambda payload, cache: {
            "meta": {"entryCount": len(payload.get("entries", [])), "etag": cache.get("etag")},
            "entries": [],
        },
        raising=False,
    )

    snapshot, _ = metadata_module._load_base_explorer_snapshot()
    assert snapshot["meta"] == {"entryCount": 0, "etag": "x"}

    monkeypatch.setattr(
        metadata_module.os.path,
        "getmtime",
        lambda _path: (_ for _ in ()).throw(OSError("missing mtime")),
        raising=False,
    )
    monkeypatch.setattr(metadata_module, "_base_full_snapshot_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_full_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_load_verified_metadata_payload", lambda: None, raising=False)

    full_snapshot, full_marker = metadata_module._load_base_full_snapshot()
    assert full_snapshot is None and full_marker is None

    monkeypatch.setattr(metadata_module, "_base_full_snapshot_cache", {"meta": {"entryCount": 1}}, raising=False)
    monkeypatch.setattr(metadata_module, "_base_full_snapshot_mtime", None, raising=False)
    cached_full, cached_full_marker = metadata_module._load_base_full_snapshot()
    assert cached_full == {"meta": {"entryCount": 1}}
    assert cached_full_marker is None

    monkeypatch.setattr(metadata_module, "_load_base_explorer_snapshot", lambda: ({}, None), raising=False)
    monkeypatch.setattr(metadata_module, "_load_verified_metadata_payload", lambda: None, raising=False)
    assert metadata_module.load_packaged_explorer_summary() == {}

    monkeypatch.setattr(metadata_module, "_load_verified_metadata_payload", lambda: verified_payload, raising=False)
    monkeypatch.setattr(metadata_module, "load_metadata_cache_entry", lambda: {}, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "build_explorer_snapshot",
        lambda _payload, _cache: {"meta": {"entryCount": 0}},
        raising=False,
    )
    assert metadata_module.load_packaged_explorer_summary() == {"entryCount": 0}

    compose_calls = []
    monkeypatch.setattr(metadata_module, "_load_base_explorer_snapshot", lambda: ({"meta": {}, "entries": []}, None), raising=False)
    monkeypatch.setattr(metadata_module, "_load_base_full_snapshot", lambda: ({"meta": {}, "entries": []}, None), raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_compose_effective_snapshot",
        lambda base_snapshot, **kwargs: compose_calls.append(kwargs) or {"meta": {}, "entries": [base_snapshot]},
        raising=False,
    )

    explorer_effective = metadata_module.load_effective_explorer_snapshot()
    full_effective = metadata_module.load_effective_full_snapshot()
    assert explorer_effective["entries"]
    assert full_effective["entries"]
    assert compose_calls == [
        {"include_detail": False},
        {"include_detail": True, "include_raw_entry": False, "compact_detail": True},
    ]


def test_lookup_compose_resolve_trust_and_verifier_edge_paths(metadata_module, monkeypatch):
    assert (
        metadata_module._entry_matches_lookup(
            {"metadataStatement": 123},
            aaguid="   ",
        )
        is False
    )
    assert metadata_module._entry_matches_lookup({"metadataStatement": 123}) is False

    session_items = [SimpleNamespace(name="a"), SimpleNamespace(name="b"), SimpleNamespace(name="c")]
    build_calls = []

    def _build_session_snapshot_entry(_item, **_kwargs):
        build_calls.append(True)
        mapping = {
            1: None,
            2: {"entryId": "session-a", "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            3: {"entryId": "session-dup", "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
        }
        return mapping[len(build_calls)]

    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: session_items, raising=False)
    monkeypatch.setattr(metadata_module, "_build_session_snapshot_entry", _build_session_snapshot_entry, raising=False)

    composed = metadata_module._compose_effective_snapshot(
        {
            "meta": "not-a-mapping",
            "entries": [
                {"entryId": "base-dup", "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                {"entryId": "base-keep", "aaguid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
                "skip-non-mapping",
            ],
        },
        include_detail=False,
    )

    assert [entry["entryId"] for entry in composed["entries"]] == ["session-a", "base-keep"]
    assert composed["meta"]["customEntryCount"] == 1

    session_payload_items = [
        SimpleNamespace(
            payload="not-a-mapping",
            uploaded_at=None,
            filename="x",
            original_filename=None,
            mtime=None,
        ),
        SimpleNamespace(
            payload={"metadataStatement": {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}},
            uploaded_at="2026-04-04T00:00:00+00:00",
            filename="y",
            original_filename=None,
            mtime=None,
        ),
    ]
    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: session_payload_items, raising=False)
    monkeypatch.setattr(metadata_module, "load_packaged_explorer_summary", lambda: {"generatedAt": "now"}, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_load_base_metadata",
        lambda: (
            SimpleNamespace(
                entries=[
                    {
                        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        "metadataStatement": {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                    },
                    {
                        "aaguid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                        "aaid": "BB#1",
                        "metadataStatement": {"aaguid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
                    },
                ]
            ),
            1.0,
        ),
        raising=False,
    )

    assert metadata_module.resolve_effective_metadata_entry(aaid="missing") is None

    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (None, None), raising=False)
    assert metadata_module.resolve_effective_metadata_entry(aaguid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb") is None

    assert metadata_module.metadata_entry_trust_anchor_status(object()) is None

    entry = metadata_module.MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())
    metadata_module._session_metadata_entry_ids = set()
    metadata_module._base_metadata_entry_ids = set()
    metadata_module._base_metadata_trust_verified = False
    assert metadata_module.metadata_entry_trust_anchor_status(entry) is False

    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (None, 77.0), raising=False)
    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: [], raising=False)
    assert metadata_module.get_mds_verifier() is None
    assert metadata_module._base_verifier_mtime == 77.0

    created = []

    class _FakeVerifier:
        def __init__(self, metadata):
            created.append(metadata)

    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (None, 88.0), raising=False)
    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: [SimpleNamespace(entry=entry)], raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_merge_metadata",
        lambda base_metadata, session_items: {
            "base": base_metadata,
            "count": len(session_items),
        },
        raising=False,
    )
    monkeypatch.setattr(metadata_module, "MdsAttestationVerifier", _FakeVerifier, raising=False)

    metadata_module.get_mds_verifier()
    assert created == [{"base": None, "count": 1}]
