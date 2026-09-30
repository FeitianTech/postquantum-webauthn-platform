from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from types import SimpleNamespace

import itsdangerous
import pytest
from fido2.mds3 import MetadataBlobPayloadEntry
from flask import ctx, g, session

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.webauthn import metadata as module
from server.app.webauthn.metadata import uploads as metadata_uploads
from server.app.webauthn.metadata import verifier as metadata_verifier
from tests.app.entry_app import entry_app


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):

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


def test_session_cookie_scheduler_branches_and_after_request_cookie(metadata_module, monkeypatch, sessions, app_config):
    touched = []
    monkeypatch.setattr(
        visitor_session,
        "note_activity",
        lambda session_id, **_kwargs: touched.append(session_id),
    )

    visitor_session._schedule_cookie("outside-context")

    with entry_app().test_request_context("/", base_url="https://localhost"):
        visitor_session._schedule_cookie("   ")
        request_ctx = ctx._cv_request.get()
        assert request_ctx._after_request_functions == []

        visitor_session._schedule_cookie("session-cookie")
        assert g._session_metadata_cookie == "session-cookie"
        assert len(request_ctx._after_request_functions) == 1

        visitor_session._schedule_cookie("session-cookie")
        assert len(request_ctx._after_request_functions) == 1

        response = request_ctx._after_request_functions[0](entry_app().response_class("ok"))
        set_cookie = response.headers["Set-Cookie"]
        assert set_cookie.startswith(f"{visitor_session.COOKIE_NAME}=")
        assert "Secure" in set_cookie
        assert "SameSite=Lax" in set_cookie
        assert "SameSite=None" not in set_cookie

        # The namespace name is signed with the application secret rather than
        # emitted verbatim, so a caller cannot rewrite it to somebody else's.
        cookie_value = set_cookie.split(";", 1)[0].split("=", 1)[1]
        assert cookie_value != "session-cookie"
        assert itsdangerous.URLSafeTimedSerializer(
            entry_app().secret_key, salt="fido.mds.session-cookie.v1"
        ).loads(cookie_value) == "session-cookie"

    assert touched == ["session-cookie", "session-cookie"]


def test_get_session_id_and_ensure_paths_cover_invalid_existing_and_error_branch(metadata_module, monkeypatch, sessions, app_config):
    assert visitor_session.current_id(create=True) is None

    scheduled = []
    monkeypatch.setattr(
        visitor_session,
        "_schedule_cookie",
        lambda identifier: scheduled.append(identifier),
    )
    monkeypatch.setattr(secrets, "token_urlsafe", lambda _n: "generated-session")

    # An unsigned cookie naming a namespace is ignored: trusting it verbatim was
    # an IDOR, since any caller could name another visitor's namespace.
    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}=cookie-session"},
    ):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) is None

    # A cookie this server signed still restores the namespace it names.
    sealed = itsdangerous.URLSafeTimedSerializer(
        entry_app().secret_key, salt="fido.mds.session-cookie.v1"
    ).dumps("cookie-session")
    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}={sealed}"},
    ):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) == "cookie-session"
        assert session[visitor_session.SESSION_KEY] == "cookie-session"

    with entry_app().test_request_context("/"):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) is None
        assert visitor_session.current_id(create=True) == "generated-session"

    with entry_app().test_request_context("/"):
        monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: None)
        with pytest.raises(RuntimeError, match="Unable to establish"):
            visitor_session.ensure_id()

    with entry_app().test_request_context("/"):
        monkeypatch.setattr(
            visitor_session,
            "current_id",
            lambda **_kwargs: "ensured-session",
        )
        assert visitor_session.ensure_id() == "ensured-session"
        assert session.permanent is True

    assert scheduled == ["cookie-session", "generated-session"]


def test_session_directory_touch_and_resolve_error_paths(metadata_module, monkeypatch, session_store, app_config, sessions):
    schedule_calls = []
    monkeypatch.setattr(
        visitor_session,
        "schedule_cleanup",
        lambda: schedule_calls.append(True),
    )

    assert mds_uploads._session_metadata_directory("", create=False) is None
    assert mds_uploads._session_metadata_directory("../escape", create=False) is None

    errors = []
    monkeypatch.setattr(
        sessions.logger,
        "error",
        lambda *args, **kwargs: errors.append((args, kwargs)),
    )
    monkeypatch.setattr(
        session_store,
        "ensure_session",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("ensure failed")),
    )

    with pytest.raises(RuntimeError, match="ensure failed"):
        mds_uploads._session_metadata_directory("session-a", create=True)

    monkeypatch.setattr(
        session_store,
        "ensure_session",
        lambda _sid: None,
    )
    assert (
        mds_uploads._session_metadata_directory("session-a", create=True, cleanup=False)
        == "session-a"
    )
    assert mds_uploads._session_metadata_directory("session-a", create=False, cleanup=True) == "session-a"

    monkeypatch.setattr(
        session_store,
        "touch_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("touch failed")),
    )
    visitor_session._touch_last_access("session-a")

    monkeypatch.setattr(
        session_store,
        "resolve_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("resolve failed")),
    )
    assert visitor_session._resolve_last_access("session-a") is None

    assert errors
    assert schedule_calls == [True]


def test_upload_and_normalisation_error_edges(metadata_module, monkeypatch, uploads, sessions):
    recorded = []
    monkeypatch.setattr(uploads, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(uploads, "git_blob_sha", lambda _content: "new-sha")
    monkeypatch.setattr(
        uploads,
        "github_list_directory",
        lambda _folder: [
            123,
            {"type": "dir", "name": "not-a-file"},
            {"type": "file", "name": "target.json", "sha": "old-sha", "path": 99},
        ],
    )
    monkeypatch.setattr(
        uploads,
        "github_upload_file",
        lambda *args, **kwargs: recorded.append((args, kwargs)),
    )

    assert metadata_uploads.maybe_store_uploaded_metadata_file("target.json", b"{}") is True
    assert recorded[0][0][0] == "metadata/target.json"
    assert recorded[0][1] == {"sha": "old-sha"}


def test_build_expand_extract_and_merge_error_branches(metadata_module, monkeypatch, entries):
    entry, _, payload = mds_entries.build_metadata_entry_components(
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
        mds_entries.expand_metadata_entry_payloads("not-a-mapping")

    monkeypatch.setattr(entries, "_clone_json_value", lambda _value: None)
    with pytest.raises(ValueError, match="could not be cloned"):
        mds_entries.expand_metadata_entry_payloads({"entries": [{"metadataStatement": {"description": "x"}}]})

    assert mds_entries._normalise_aaguid(123) is None

    class _NoMappingEntry:
        aaguid = None
        metadata_statement = None
        metadataStatement = "not-a-mapping"

    assert mds_entries._extract_entry_aaguid(_NoMappingEntry()) is None

    session_entry_one = MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())
    session_entry_two = MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())

    item_one = mds_uploads.SessionMetadataItem(
        filename="one.json",
        payload=_minimal_entry_payload(),
        legal_header=None,
        entry=session_entry_one,
        uploaded_at="2026-04-04T00:00:00+00:00",
        original_filename="one.json",
        mtime=1.0,
    )
    item_two = mds_uploads.SessionMetadataItem(
        filename="two.json",
        payload=_minimal_entry_payload(),
        legal_header="Session Legal",
        entry=session_entry_two,
        uploaded_at="2026-04-04T00:00:00+00:00",
        original_filename="two.json",
        mtime=2.0,
    )

    monkeypatch.setattr(
        entries,
        "_extract_entry_aaguid",
        lambda value: mds_entries._normalise_aaguid(str(getattr(value, "aaguid", ""))),
    )

    merged = metadata_verifier._merge_metadata(None, [item_one, item_two])
    assert merged.legal_header == "Session Legal"
    assert len(merged.entries) == 1


class _NotJSONSerializable:
    pass


def test_save_list_delete_serialize_and_datetime_edge_paths(metadata_module, monkeypatch, sessions, entries, blob, session_store):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-a")
    monkeypatch.setattr(sessions, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a")
    monkeypatch.setattr(
        entries,
        "build_metadata_entry_components",
        lambda _raw: (
            MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload()),
            None,
            {"metadataStatement": {"description": "x"}},
        ),
    )

    with pytest.raises(ValueError, match="unsupported types"):
        mds_uploads.save_session_metadata_item({"bad": _NotJSONSerializable()})

    monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: "session-a")
    monkeypatch.setattr(sessions, "_session_metadata_directory", lambda *_args, **_kwargs: None)
    assert mds_uploads.list_session_metadata_items() == []

    monkeypatch.setattr(sessions, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a")
    monkeypatch.setattr(visitor_session, "note_activity", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        session_store,
        "list_files",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("list failed")),
    )
    assert mds_uploads.list_session_metadata_items() == []

    monkeypatch.setattr(
        session_store,
        "list_files",
        lambda _sid: ["entry.json"],
    )
    monkeypatch.setattr(
        session_store,
        "read_file",
        lambda _sid, _name: json.dumps(_minimal_entry_payload()).encode("utf-8"),
    )
    monkeypatch.setattr(
        sessions,
        "_load_session_metadata_info",
        lambda _sid, _name: {
            "uploaded_at": " 2026-04-04T00:00:00+00:00 ",
            "original_filename": " original.json ",
        },
    )
    monkeypatch.setattr(
        session_store,
        "file_mtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("mtime failed")),
    )

    listed = mds_uploads.list_session_metadata_items("session-a")
    assert len(listed) == 1
    assert listed[0].mtime is None
    assert listed[0].uploaded_at == "2026-04-04T00:00:00+00:00"
    assert listed[0].original_filename == "original.json"

    monkeypatch.setattr(sessions, "_session_metadata_directory", lambda *_args, **_kwargs: None)
    assert mds_uploads.delete_session_metadata_item("entry.json", session_id="session-a") is False

    monkeypatch.setattr(sessions, "_session_metadata_directory", lambda *_args, **_kwargs: "session-a")
    monkeypatch.setattr(
        session_store,
        "file_exists",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("exists failed")),
    )
    assert mds_uploads.delete_session_metadata_item("entry.json", session_id="session-a") is False

    delete_calls = []

    def _delete_file(_sid, name, *, missing_ok=True):
        delete_calls.append((name, missing_ok))
        if name.endswith(mds_uploads._SESSION_METADATA_INFO_SUFFIX):
            raise OSError("info delete ignored")

    monkeypatch.setattr(
        session_store,
        "file_exists",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        session_store,
        "delete_file",
        _delete_file,
    )
    monkeypatch.setattr(sessions, "_prune_session_metadata_directory", lambda *_args, **_kwargs: None)

    assert mds_uploads.delete_session_metadata_item("entry.json", session_id="session-a") is True
    assert delete_calls[0] == ("entry.json", False)
    assert delete_calls[1] == ("entry.json.meta.json", True)

    serialized = mds_uploads.serialize_session_metadata_item(
        mds_uploads.SessionMetadataItem(
            filename="stored.json",
            payload={"metadataStatement": {"description": "Demo"}},
            legal_header="Legal Header",
            entry=MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload()),
            uploaded_at=None,
            original_filename=None,
            mtime=None,
        )
    )
    assert serialized["source"] == {"storedFilename": "stored.json"}
    assert serialized["legalHeader"] == "Legal Header"

    assert mds_files.parse_http_datetime(None) is None
    monkeypatch.setattr(mds_files, "parsedate_to_datetime", lambda _value: datetime(2026, 1, 1, 0, 0, 0))
    parsed = mds_files.parse_http_datetime("Wed, 01 Jan 2026 00:00:00 GMT")
    assert parsed is not None and parsed.tzinfo is not None

    assert mds_files.format_last_modified(None) is None
    assert mds_files.format_last_modified("Thu, 01 Jan 1970 00:00:00 GMT") == "2026-01-01T00:00:00+00:00"


def test_cache_and_bootstrap_fallback_helpers(metadata_module, monkeypatch, tmp_path, metadata_state, blob, effective):
    # The cache first, in a directory of its own, then the snapshot in another.
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path / "cache"))
    cache_path = tmp_path / "cache" / "fido-mds3.verified.json.meta.json"

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("[]", encoding="utf-8")
    assert mds_cache.load_metadata_cache_entry() == {}

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
    loaded_cache = mds_cache.load_metadata_cache_entry()
    assert loaded_cache["last_modified_iso"] == "2015-10-21T07:28:00+00:00"
    assert loaded_cache["etag"] == "etag-value"

    real_load_base_metadata = blob._load_base_metadata

    monkeypatch.setattr(blob, "_load_base_metadata", lambda: (None, None))
    assert mds_cache.load_cached_metadata_snapshot() is False
    monkeypatch.setattr(blob, "_load_base_metadata", lambda: (object(), None))
    assert mds_cache.load_cached_metadata_snapshot() is True

    monkeypatch.setattr(blob, "_load_base_metadata", real_load_base_metadata)

    monkeypatch.setattr(
        os.path,
        "getmtime",
        lambda _path: (_ for _ in ()).throw(OSError("mtime missing")),
    )
    monkeypatch.setattr(blob, "_load_verified_metadata_fallback", lambda: (None, None))
    metadata_value, marker = blob._load_base_metadata()
    assert metadata_value is None and marker is None
    assert mds_cache.CACHE.metadata_source is None
    assert mds_cache.CACHE.trust_verified is None

    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir()
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(snapshot_dir))
    verified_path = snapshot_dir / "fido-mds3.verified.json"

    missing_loaded, _ = mds_cache._load_verified_metadata_fallback()
    assert missing_loaded is None

    verified_path.write_text("{not-json", encoding="utf-8")
    invalid_loaded, _ = mds_cache._load_verified_metadata_fallback()
    assert invalid_loaded is None

    verified_path.write_text("[]", encoding="utf-8")
    assert mds_cache._load_verified_metadata_payload() is None

    verified_payload = {
        "legalHeader": "L",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [],
    }
    verified_path.write_text(json.dumps(verified_payload), encoding="utf-8")

    monkeypatch.setattr(os.path, "getmtime", lambda path: 20.0 if path == str(verified_path) else 10.0)
    # The explorer, the verified snapshot, and their metas.
    explorer_cache_marker = (10.0, 20.0, 10.0, 10.0)
    monkeypatch.setattr(mds_cache.CACHE, "explorer", {"meta": {"entryCount": 9}})
    monkeypatch.setattr(mds_cache.CACHE, "explorer_mtime", explorer_cache_marker)
    cached_snapshot, cached_marker = mds_cache._load_base_explorer_snapshot()
    assert cached_snapshot == {"meta": {"entryCount": 9}}
    assert cached_marker == explorer_cache_marker

    explorer_path = snapshot_dir / "fido-mds3.explorer.json"
    explorer_path.write_text("{invalid-json", encoding="utf-8")
    monkeypatch.setattr(mds_cache.CACHE, "explorer", None)
    monkeypatch.setattr(mds_cache.CACHE, "explorer_mtime", None)
    monkeypatch.setattr(blob, "load_metadata_cache_entry", lambda: {"etag": "x"})
    monkeypatch.setattr(
        blob,
        "build_explorer_snapshot",
        lambda payload, cache: {
            "meta": {"entryCount": len(payload.get("entries", [])), "etag": cache.get("etag")},
            "entries": [],
        },
    )

    snapshot, _ = mds_cache._load_base_explorer_snapshot()
    assert snapshot["meta"] == {"entryCount": 0, "etag": "x"}

    monkeypatch.setattr(
        os.path,
        "getmtime",
        lambda _path: (_ for _ in ()).throw(OSError("missing mtime")),
    )
    monkeypatch.setattr(mds_cache.CACHE, "full", None)
    monkeypatch.setattr(mds_cache.CACHE, "full_mtime", None)
    monkeypatch.setattr(blob, "_load_verified_metadata_payload", lambda: None)

    full_snapshot, full_marker = mds_cache._load_base_full_snapshot()
    assert full_snapshot is None and full_marker == (None, None, None, None)

    monkeypatch.setattr(mds_cache.CACHE, "full", {"meta": {"entryCount": 1}})
    monkeypatch.setattr(mds_cache.CACHE, "full_mtime", (None, None, None, None))
    cached_full, cached_full_marker = mds_cache._load_base_full_snapshot()
    assert cached_full == {"meta": {"entryCount": 1}}
    assert cached_full_marker == (None, None, None, None)

    monkeypatch.setattr(blob, "_load_base_explorer_snapshot", lambda: ({}, None))
    monkeypatch.setattr(blob, "_load_verified_metadata_payload", lambda: None)
    assert mds_cache.load_packaged_explorer_summary() == {}

    monkeypatch.setattr(blob, "_load_verified_metadata_payload", lambda: verified_payload)
    monkeypatch.setattr(blob, "load_metadata_cache_entry", lambda: {})
    monkeypatch.setattr(
        blob,
        "build_explorer_snapshot",
        lambda _payload, _cache: {"meta": {"entryCount": 0}},
    )
    assert mds_cache.load_packaged_explorer_summary() == {"entryCount": 0}

    compose_calls = []
    monkeypatch.setattr(blob, "_load_base_explorer_snapshot", lambda: ({"meta": {}, "entries": []}, None))
    monkeypatch.setattr(blob, "_load_base_full_snapshot", lambda: ({"meta": {}, "entries": []}, None))
    monkeypatch.setattr(
        effective,
        "_compose_effective_snapshot",
        lambda base_snapshot, **kwargs: compose_calls.append(kwargs) or {"meta": {}, "entries": [base_snapshot]},
    )

    full_effective = mds_effective.load_effective_full_snapshot()
    assert full_effective["entries"]
    assert compose_calls == [
        {"include_detail": True, "include_raw_entry": False, "compact_detail": True},
    ]


def test_lookup_compose_resolve_trust_and_verifier_edge_paths(metadata_module, metadata_state, monkeypatch, blob, sessions, effective, verifier):
    assert (
        mds_effective._entry_matches_lookup(
            {"metadataStatement": 123},
            aaguid="   ",
        )
        is False
    )
    assert mds_effective._entry_matches_lookup({"metadataStatement": 123}) is False

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

    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: session_items)
    monkeypatch.setattr(effective, "_build_session_snapshot_entry", _build_session_snapshot_entry)

    composed = mds_effective._compose_effective_snapshot(
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
    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: session_payload_items)
    monkeypatch.setattr(blob, "load_packaged_explorer_summary", lambda: {"generatedAt": "now"})
    monkeypatch.setattr(
        blob,
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
    )

    assert mds_effective.resolve_effective_metadata_entry(aaid="missing") is None

    monkeypatch.setattr(blob, "_load_base_metadata", lambda: (None, None))
    assert mds_effective.resolve_effective_metadata_entry(aaguid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb") is None

    assert metadata_verifier.metadata_entry_trust_anchor_status(object()) is None

    entry = MetadataBlobPayloadEntry.from_dict(_minimal_entry_payload())
    mds_cache.CACHE.entry_ids = set()
    mds_cache.CACHE.trust_verified = False
    assert metadata_verifier.metadata_entry_trust_anchor_status(entry) is None

    monkeypatch.setattr(blob, "_load_base_metadata", lambda: (None, 77.0))
    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: [])
    assert metadata_verifier.get_mds_verifier() is None
    assert mds_cache.CACHE.verifier_mtime == 77.0

    created = []

    class _FakeVerifier:
        def __init__(self, metadata):
            created.append(metadata)

    monkeypatch.setattr(blob, "_load_base_metadata", lambda: (None, 88.0))
    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: [SimpleNamespace(entry=entry)])
    monkeypatch.setattr(
        verifier,
        "_merge_metadata",
        lambda base_metadata, session_items: {
            "base": base_metadata,
            "count": len(session_items),
        },
    )
    monkeypatch.setattr(verifier, "MdsAttestationVerifier", _FakeVerifier)

    metadata_verifier.get_mds_verifier()
    assert created == [{"base": None, "count": 1}]


def test_the_never_raised_metadata_download_error_is_gone():
    # Nothing raised or caught it; it was exported for nobody.
    import importlib
    import pkgutil

    import server.app.webauthn.metadata as package

    for info in pkgutil.iter_modules(package.__path__, f"{package.__name__}."):
        assert not hasattr(importlib.import_module(info.name), "MetadataDownloadError")
