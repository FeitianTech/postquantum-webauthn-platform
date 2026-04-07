from __future__ import annotations

import io
import json
from types import MappingProxyType, SimpleNamespace

import pytest


@pytest.fixture
def metadata_module(monkeypatch):
    module = pytest.importorskip("server.app.metadata")
    monkeypatch.setattr(module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_explorer_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_mtime", None, raising=False)
    return module


def test_metadata_validation_and_info_loader_residual_guards(metadata_module, monkeypatch):
    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename(123)
    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename("entry.txt")

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "read_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing")),
        raising=False,
    )
    assert metadata_module._load_session_metadata_info("session", "entry.meta.json") == {}

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "read_file",
        lambda *_args, **_kwargs: b"[]",
        raising=False,
    )
    assert metadata_module._load_session_metadata_info("session", "entry.meta.json") == {}


def test_metadata_build_and_expand_residual_paths(metadata_module):
    entry, legal_header, payload = metadata_module.build_metadata_entry_components(
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
    assert metadata_module.expand_metadata_entry_payloads(raw_payload) == [raw_payload]


def test_save_session_metadata_item_runtime_warning_and_mtime_fallback(metadata_module, monkeypatch):
    monkeypatch.setattr(metadata_module, "ensure_metadata_session_id", lambda: "session-1", raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_session_metadata_directory",
        lambda *_args, **_kwargs: None,
        raising=False,
    )
    with pytest.raises(RuntimeError, match="Unable to resolve session metadata storage path"):
        metadata_module.save_session_metadata_item({"anything": True})

    monkeypatch.setattr(
        metadata_module,
        "_session_metadata_directory",
        lambda *_args, **_kwargs: "session-dir",
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "build_metadata_entry_components",
        lambda _payload: ({"entry": "ok"}, None, {"payload": True}),
        raising=False,
    )

    def _write_file(_directory, filename, *_args, **_kwargs):
        if filename.endswith(metadata_module._SESSION_METADATA_INFO_SUFFIX):
            raise RuntimeError("info-write-failure")

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "write_file",
        _write_file,
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "file_mtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("mtime-failure")),
        raising=False,
    )

    saved = metadata_module.save_session_metadata_item({"payload": "ok"}, original_filename="demo.json")
    assert saved.mtime is None
    assert saved.original_filename == "demo.json"


def test_metadata_cache_and_verified_fallback_residual_error_paths(metadata_module, monkeypatch):
    monkeypatch.setattr(
        metadata_module,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("open-failure")),
        raising=False,
    )
    assert metadata_module.load_metadata_cache_entry() == {}

    monkeypatch.setattr(metadata_module.os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("no-mtime")), raising=False)
    monkeypatch.setattr(
        metadata_module,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("missing")),
        raising=False,
    )
    loaded, mtime = metadata_module._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime is None

    monkeypatch.setattr(metadata_module.os.path, "getmtime", lambda _path: 123.0, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "open",
        lambda *_args, **_kwargs: io.StringIO("{invalid-json"),
        raising=False,
    )
    loaded, mtime = metadata_module._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime == 123.0


def test_base_explorer_snapshot_and_summary_and_resolution_session_match(metadata_module, monkeypatch):
    def _getmtime(path):
        raise OSError("mtime-missing")

    monkeypatch.setattr(metadata_module.os.path, "getmtime", _getmtime, raising=False)
    monkeypatch.setattr(metadata_module, "_load_verified_metadata_payload", lambda: None, raising=False)
    snapshot, marker = metadata_module._load_base_explorer_snapshot()
    assert snapshot is None
    assert marker == (None, None)

    def _getmtime_ordered(path):
        if path == metadata_module.MDS_EXPLORER_PATH:
            return 10.0
        return 5.0

    monkeypatch.setattr(metadata_module.os.path, "getmtime", _getmtime_ordered, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("explorer-open-failure")),
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "_load_verified_metadata_payload",
        lambda: {"legalHeader": "L", "no": 1, "nextUpdate": "2099-01-01", "entries": []},
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "build_explorer_snapshot",
        lambda _payload, _cache: {"meta": {"entryCount": 0}},
        raising=False,
    )
    snapshot, marker = metadata_module._load_base_explorer_snapshot()
    assert snapshot == {"meta": {"entryCount": 0}}
    assert marker == (10.0, 5.0)

    monkeypatch.setattr(
        metadata_module,
        "_load_base_explorer_snapshot",
        lambda: ({"meta": MappingProxyType({"entryCount": 2})}, (1.0, 1.0)),
        raising=False,
    )
    assert metadata_module.load_packaged_explorer_summary() == {"entryCount": 2}

    item = SimpleNamespace(payload={"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}, uploaded_at="now")
    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: [item], raising=False)
    monkeypatch.setattr(metadata_module, "_entry_matches_lookup", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(metadata_module, "_session_item_source_info", lambda _item: {"source": "session"}, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "build_explorer_entry",
        lambda payload, **_kwargs: {"source": "session", "payload": payload},
        raising=False,
    )
    resolved = metadata_module.resolve_effective_metadata_entry(entry_id="any")
    assert resolved["source"] == "session"