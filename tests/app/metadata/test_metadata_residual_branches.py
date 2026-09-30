from __future__ import annotations

import io
import os
from types import MappingProxyType, SimpleNamespace

import pytest

from server.app.mds import cache as mds_cache
from server.app.mds import files as mds_files
from server.app.webauthn import metadata as module
from server.app.webauthn.metadata import effective as metadata_effective
from server.app.webauthn.metadata import entries as metadata_entries
from server.app.webauthn.metadata import sessions as metadata_sessions
from server.app.webauthn.metadata import state as metadata_state


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    return module


def test_metadata_validation_and_info_loader_residual_guards(metadata_module, monkeypatch, session_store):
    with pytest.raises(ValueError):
        metadata_sessions._validate_session_metadata_filename(123)
    with pytest.raises(ValueError):
        metadata_sessions._validate_session_metadata_filename("entry.txt")

    monkeypatch.setattr(
        session_store,
        "read_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing")),
    )
    assert metadata_sessions._load_session_metadata_info("session", "entry.meta.json") == {}

    monkeypatch.setattr(
        session_store,
        "read_file",
        lambda *_args, **_kwargs: b"[]",
    )
    assert metadata_sessions._load_session_metadata_info("session", "entry.meta.json") == {}


def test_metadata_build_and_expand_residual_paths(metadata_module):
    entry, legal_header, payload = metadata_entries.build_metadata_entry_components(
        {
            "timeOfLastStatusChange": " 2026-01-01 ",
            "attestationCertificateKeyIdentifiers": ["ab"],
            "metadataStatement": {"description": "demo"},
            "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}],
        }
    )
    assert legal_header is None
    assert payload["timeOfLastStatusChange"] == "2026-01-01"
    assert payload["attestationCertificateKeyIdentifiers"] == ["ab"]
    assert entry["metadataStatement"]["description"] == "demo"

    raw_payload = {"metadataStatement": {"description": "single-entry"}}
    assert metadata_entries.expand_metadata_entry_payloads(raw_payload) == [raw_payload]


def test_save_session_metadata_item_runtime_warning_and_mtime_fallback(metadata_module, monkeypatch, sessions, entries, session_store):
    monkeypatch.setattr(sessions, "ensure_metadata_session_id", lambda: "session-1")
    monkeypatch.setattr(
        sessions,
        "_session_metadata_directory",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(RuntimeError, match="Unable to resolve session metadata storage path"):
        metadata_sessions.save_session_metadata_item({"anything": True})

    monkeypatch.setattr(
        sessions,
        "_session_metadata_directory",
        lambda *_args, **_kwargs: "session-dir",
    )
    monkeypatch.setattr(
        entries,
        "build_metadata_entry_components",
        lambda _payload: ({"entry": "ok"}, None, {"payload": True}),
    )

    def _write_file(_directory, filename, *_args, **_kwargs):
        if filename.endswith(metadata_state._SESSION_METADATA_INFO_SUFFIX):
            raise RuntimeError("info-write-failure")

    monkeypatch.setattr(
        session_store,
        "write_file",
        _write_file,
    )
    monkeypatch.setattr(
        session_store,
        "file_mtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("mtime-failure")),
    )

    saved = metadata_sessions.save_session_metadata_item({"payload": "ok"}, original_filename="demo.json")
    assert saved.mtime is None
    assert saved.original_filename == "demo.json"


def test_metadata_cache_and_verified_fallback_residual_error_paths(metadata_module, monkeypatch, blob):
    monkeypatch.setattr(
        blob,
        "open",  # shadows the builtin; the module has none
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("open-failure")),
        raising=False,
    )
    assert mds_cache.load_metadata_cache_entry() == {}

    monkeypatch.setattr(os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("no-mtime")))
    monkeypatch.setattr(
        blob,
        "open",  # shadows the builtin; the module has none
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("missing")),
        raising=False,
    )
    loaded, mtime = mds_cache._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime is None

    monkeypatch.setattr(os.path, "getmtime", lambda _path: 123.0)
    monkeypatch.setattr(
        blob,
        "open",  # shadows the builtin; the module has none
        lambda *_args, **_kwargs: io.StringIO("{invalid-json"),
        raising=False,
    )
    loaded, mtime = mds_cache._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime == 123.0


def test_base_explorer_snapshot_and_summary_and_resolution_session_match(metadata_module, monkeypatch, blob, sessions, effective):
    def _getmtime(path):
        raise OSError("mtime-missing")

    monkeypatch.setattr(os.path, "getmtime", _getmtime)
    monkeypatch.setattr(blob, "_load_verified_metadata_payload", lambda: None)
    snapshot, marker = mds_cache._load_base_explorer_snapshot()
    assert snapshot is None
    assert marker == (None, None, None, None)

    def _getmtime_ordered(path):
        if path == blob._path(mds_files.EXPLORER):
            return 10.0
        return 5.0

    monkeypatch.setattr(os.path, "getmtime", _getmtime_ordered)
    monkeypatch.setattr(
        blob,
        "open",  # shadows the builtin; the module has none
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("explorer-open-failure")),
        raising=False,
    )
    monkeypatch.setattr(
        blob,
        "_load_verified_metadata_payload",
        lambda: {"legalHeader": "L", "no": 1, "nextUpdate": "2099-01-01", "entries": []},
    )
    monkeypatch.setattr(
        blob,
        "build_explorer_snapshot",
        lambda _payload, _cache: {"meta": {"entryCount": 0}},
    )
    snapshot, marker = mds_cache._load_base_explorer_snapshot()
    assert snapshot == {"meta": {"entryCount": 0}}
    assert marker == (10.0, 5.0, 5.0, 5.0)

    monkeypatch.setattr(
        blob,
        "_load_base_explorer_snapshot",
        lambda: ({"meta": MappingProxyType({"entryCount": 2})}, (1.0, 1.0)),
    )
    assert mds_cache.load_packaged_explorer_summary() == {"entryCount": 2}

    item = SimpleNamespace(payload={"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}, uploaded_at="now")
    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: [item])
    monkeypatch.setattr(effective, "_entry_matches_lookup", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(effective, "_session_item_source_info", lambda _item: {"source": "session"})
    monkeypatch.setattr(
        effective,
        "build_explorer_entry",
        lambda payload, **_kwargs: {"source": "session", "payload": payload},
    )
    resolved = metadata_effective.resolve_effective_metadata_entry(entry_id="any")
    assert resolved["source"] == "session"
