from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import tools.update_mds_snapshot as updater


@pytest.fixture
def isolated_mds_paths(monkeypatch, tmp_path):
    static_dir = tmp_path / "frontend" / "static"
    monkeypatch.setattr(updater, "FRONTEND_STATIC_DIR", static_dir)
    monkeypatch.setattr(updater, "MDS_METADATA_PATH", static_dir / "blob.jwt")
    monkeypatch.setattr(updater, "MDS_METADATA_VERIFIED_PATH", static_dir / "fido-mds3.verified.json")
    monkeypatch.setattr(
        updater,
        "MDS_METADATA_CACHE_PATH",
        static_dir / "fido-mds3.verified.json.meta.json",
    )
    monkeypatch.setattr(updater, "MDS_EXPLORER_PATH", static_dir / "fido-mds3.explorer.json")
    monkeypatch.setattr(
        updater,
        "MDS_EXPLORER_META_PATH",
        static_dir / "fido-mds3.explorer.json.meta.json",
    )
    monkeypatch.setattr(
        updater,
        "MDS_BOOTSTRAP_JS_PATH",
        static_dir / "fido-mds3.explorer.bootstrap.js",
    )
    monkeypatch.setattr(
        updater,
        "MDS_BOOTSTRAP_META_PATH",
        static_dir / "fido-mds3.explorer.bootstrap.meta.json",
    )
    return static_dir


def test_module_import_inserts_repo_root_when_missing(monkeypatch):
    module_name = "_update_mds_snapshot_path_branch_test"
    module_file = Path(updater.__file__).resolve()
    repo_root = str(module_file.parents[1])

    monkeypatch.setattr(sys, "path", [p for p in sys.path if p != repo_root])

    spec = importlib.util.spec_from_file_location(module_name, module_file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        assert sys.path[0] == repo_root
    finally:
        sys.modules.pop(module_name, None)


def test_module_import_does_not_require_flask_dependency(monkeypatch):
    module_name = "_update_mds_snapshot_no_flask_import_test"
    module_file = Path(updater.__file__).resolve()
    original_import = builtins.__import__

    def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "flask" or name.startswith("flask."):
            raise AssertionError("update_mds_snapshot import unexpectedly requires flask")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _guarded_import)

    spec = importlib.util.spec_from_file_location(module_name, module_file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)


def test_parse_http_datetime_handles_invalid_and_timezone_branches(monkeypatch):
    assert updater._parse_http_datetime(None) is None

    def _raise_value_error(_value):
        raise ValueError("bad datetime")

    monkeypatch.setattr(updater, "parsedate_to_datetime", _raise_value_error)
    assert updater._parse_http_datetime("bad") is None

    monkeypatch.setattr(
        updater,
        "parsedate_to_datetime",
        lambda _value: datetime(2026, 4, 1, 12, 0, 0),
    )
    parsed_naive = updater._parse_http_datetime("Wed, 01 Apr 2026 12:00:00 GMT")
    assert parsed_naive == datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)

    pacific = timezone.utc
    monkeypatch.setattr(
        updater,
        "parsedate_to_datetime",
        lambda _value: datetime(2026, 4, 1, 12, 0, 0, tzinfo=pacific),
    )
    parsed_aware = updater._parse_http_datetime("Wed, 01 Apr 2026 12:00:00 GMT")
    assert parsed_aware == datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_format_last_modified_header_returns_iso_or_original(monkeypatch):
    dt = datetime(2026, 4, 2, 0, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(updater, "_parse_http_datetime", lambda _value: dt)
    assert updater.format_last_modified_header("anything") == "2026-04-02T00:00:00+00:00"

    monkeypatch.setattr(updater, "_parse_http_datetime", lambda _value: None)
    assert updater.format_last_modified_header("raw-header") == "raw-header"


def test_store_metadata_cache_entry_writes_expected_payload(isolated_mds_paths):
    updater.store_metadata_cache_entry(
        last_modified_header="Wed, 01 Apr 2026 12:00:00 GMT",
        last_modified_iso="2026-04-01T12:00:00+00:00",
        etag="\"abc\"",
        fetched_at="2026-04-03T12:00:00+00:00",
        generated_at="2026-04-03T12:00:01+00:00",
        snapshot_no=321,
        next_update="2026-05-01",
        entry_count=7,
    )

    cache_payload = json.loads(updater.MDS_METADATA_CACHE_PATH.read_text(encoding="utf-8"))
    assert cache_payload == {
        "entryCount": 7,
        "etag": '"abc"',
        "fetched_at": "2026-04-03T12:00:00+00:00",
        "generated_at": "2026-04-03T12:00:01+00:00",
        "last_modified": "Wed, 01 Apr 2026 12:00:00 GMT",
        "last_modified_iso": "2026-04-01T12:00:00+00:00",
        "nextUpdate": "2026-05-01",
        "no": 321,
    }


def test_store_metadata_cache_entry_swallows_oserror(monkeypatch, isolated_mds_paths):
    def _raise_oserror(self, _text, encoding="utf-8"):
        raise OSError("disk full")

    monkeypatch.setattr(updater.Path, "write_text", _raise_oserror)

    updater.store_metadata_cache_entry(
        last_modified_header=None,
        last_modified_iso=None,
        etag=None,
    )


def test_fetch_remote_blob_uses_expected_request_contract(monkeypatch):
    class _FakeResponse:
        def __init__(self):
            self.headers = {"Last-Modified": "Wed, 01 Apr 2026 12:00:00 GMT", "ETag": '"etag"'}

        def read(self):
            return b"jwt-bytes"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_urlopen(request, timeout):
        assert request.full_url == updater.MDS_METADATA_URL
        assert timeout == 120
        headers = {k.lower(): v for k, v in request.header_items()}
        assert headers["user-agent"] == "webauthnlab-mds-updater"
        return _FakeResponse()

    monkeypatch.setattr(updater.urllib.request, "urlopen", _fake_urlopen)

    blob, last_modified, etag = updater._fetch_remote_blob()
    assert blob == b"jwt-bytes"
    assert last_modified == "Wed, 01 Apr 2026 12:00:00 GMT"
    assert etag == '"etag"'


def test_write_blob_write_if_changed_and_serialisers(isolated_mds_paths, tmp_path):
    updater._write_blob(b"initial")
    assert updater.MDS_METADATA_PATH.read_bytes() == b"initial"

    target = tmp_path / "nested" / "payload.txt"
    assert updater._write_if_changed(target, "hello") is True
    assert target.read_text(encoding="utf-8") == "hello"
    assert updater._write_if_changed(target, "hello") is False
    assert updater._write_if_changed(target, b"world") is True
    assert target.read_bytes() == b"world"

    serialised_json = updater._serialise_json({"b": 2, "a": 1})
    assert serialised_json == '{\n  "a": 1,\n  "b": 2\n}\n'

    bootstrap_script = updater._serialise_bootstrap_script({"b": 2, "a": 1})
    assert bootstrap_script.startswith("(function () {\n")
    assert bootstrap_script.endswith("})();\n")
    assignment_line = bootstrap_script.splitlines()[1]
    prefix = "  window.__INITIAL_MDS_SNAPSHOT__ = "
    assert assignment_line.startswith(prefix)
    payload_json = assignment_line[len(prefix) : -1]
    assert payload_json == '{"a":1,"b":2}'
    assert json.loads(payload_json) == {"a": 1, "b": 2}


def test_load_existing_cache_handles_missing_invalid_and_non_dict(isolated_mds_paths):
    assert updater._load_existing_cache() == {}

    updater.MDS_METADATA_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    updater.MDS_METADATA_CACHE_PATH.write_text("not-json", encoding="utf-8")
    assert updater._load_existing_cache() == {}

    updater.MDS_METADATA_CACHE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    assert updater._load_existing_cache() == {}

    updater.MDS_METADATA_CACHE_PATH.write_text('{"fetched_at": "x"}', encoding="utf-8")
    assert updater._load_existing_cache() == {"fetched_at": "x"}


def test_build_cache_state_uses_existing_values_when_blob_unchanged(monkeypatch):
    fixed_now = datetime(2026, 4, 3, 12, 0, 0, tzinfo=timezone.utc)

    class _FixedDateTime:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return fixed_now

    monkeypatch.setattr(updater, "datetime", _FixedDateTime)

    existing_cache = {
        "fetched_at": "2026-03-30T00:00:00+00:00",
        "generated_at": "2026-03-30T00:00:01+00:00",
        "last_modified": "Wed, 30 Mar 2026 00:00:00 GMT",
        "last_modified_iso": "2026-03-30T00:00:00+00:00",
        "etag": '"old"',
    }
    verified_snapshot = {"no": 88, "nextUpdate": "2026-09-01", "entries": [{}, {}]}

    state = updater._build_cache_state(
        last_modified="Wed, 03 Apr 2026 00:00:00 GMT",
        etag='"new"',
        existing_cache=existing_cache,
        blob_unchanged=True,
        verified_snapshot=verified_snapshot,
    )

    assert state == {
        "last_modified": "Wed, 30 Mar 2026 00:00:00 GMT",
        "last_modified_iso": "2026-03-30T00:00:00+00:00",
        "etag": '"old"',
        "fetched_at": "2026-03-30T00:00:00+00:00",
        "generated_at": "2026-03-30T00:00:01+00:00",
        "no": 88,
        "nextUpdate": "2026-09-01",
        "entryCount": 2,
    }


def test_build_cache_state_sets_fresh_values_when_blob_changed(monkeypatch):
    fixed_now = datetime(2026, 4, 3, 13, 0, 0, tzinfo=timezone.utc)

    class _FixedDateTime:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return fixed_now

    monkeypatch.setattr(updater, "datetime", _FixedDateTime)

    state = updater._build_cache_state(
        last_modified="Wed, 03 Apr 2026 00:00:00 GMT",
        etag='"new"',
        existing_cache={},
        blob_unchanged=False,
        verified_snapshot={"no": 12, "nextUpdate": "2026-10-01", "entries": "not-a-list"},
    )

    assert state == {
        "last_modified": "Wed, 03 Apr 2026 00:00:00 GMT",
        "last_modified_iso": "2026-04-03T00:00:00+00:00",
        "etag": '"new"',
        "fetched_at": "2026-04-03T13:00:00+00:00",
        "generated_at": "2026-04-03T13:00:00+00:00",
        "no": 12,
        "nextUpdate": "2026-10-01",
        "entryCount": 0,
    }


def test_build_verified_snapshot_and_write_cache_state_delegation(monkeypatch, isolated_mds_paths):
    seen = {}

    def _fake_parse_blob(blob, cert):
        seen["blob"] = blob
        seen["cert"] = cert
        return {"entries": [], "no": 1}

    monkeypatch.setattr(updater, "parse_blob", _fake_parse_blob)
    verified = updater._build_verified_snapshot(b"blob-data")
    assert verified == {"entries": [], "no": 1}
    assert seen["blob"] == b"blob-data"
    assert seen["cert"] == updater.FIDO_METADATA_TRUST_ROOT_CERT

    delegated = {}

    def _fake_write_if_changed(path: Path, payload: str | bytes):
        delegated["path"] = path
        delegated["payload"] = payload
        return True

    monkeypatch.setattr(updater, "_write_if_changed", _fake_write_if_changed)
    assert updater._write_cache_state({"a": 1}) is True
    assert delegated["path"] == updater.MDS_METADATA_CACHE_PATH
    assert delegated["payload"] == '{\n  "a": 1\n}\n'


def test_main_reports_refresh_then_up_to_date(monkeypatch, isolated_mds_paths, capsys):
    fixed_now = datetime(2026, 4, 3, 14, 0, 0, tzinfo=timezone.utc)

    class _FixedDateTime:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return fixed_now

    monkeypatch.setattr(updater, "datetime", _FixedDateTime)
    monkeypatch.setattr(
        updater,
        "_fetch_remote_blob",
        lambda: (b"same-blob", "Wed, 03 Apr 2026 00:00:00 GMT", '"etag"'),
    )
    monkeypatch.setattr(
        updater,
        "_build_verified_snapshot",
        lambda _blob: {"entries": [{"aaguid": "x"}], "no": 99, "nextUpdate": "2026-12-01"},
    )
    monkeypatch.setattr(
        updater,
        "build_explorer_snapshot",
        lambda _verified, _cache: {"entries": [{"name": "demo"}], "meta": {"kind": "explorer"}},
    )
    monkeypatch.setattr(
        updater,
        "build_bootstrap_snapshot",
        lambda _verified, _cache: {"entries": [{"name": "demo"}], "meta": {"kind": "bootstrap"}},
    )

    first = updater.main()
    first_output = capsys.readouterr().out
    assert first == 0
    assert "Packaged metadata snapshot refreshed." in first_output

    assert updater.MDS_METADATA_PATH.read_bytes() == b"same-blob"
    assert json.loads(updater.MDS_METADATA_VERIFIED_PATH.read_text(encoding="utf-8"))["no"] == 99
    assert json.loads(updater.MDS_EXPLORER_META_PATH.read_text(encoding="utf-8")) == {"kind": "explorer"}
    assert json.loads(updater.MDS_BOOTSTRAP_META_PATH.read_text(encoding="utf-8")) == {"kind": "bootstrap"}
    assert "window.__INITIAL_MDS_SNAPSHOT__" in updater.MDS_BOOTSTRAP_JS_PATH.read_text(encoding="utf-8")

    second = updater.main()
    second_output = capsys.readouterr().out
    assert second == 0
    assert "already up to date" in second_output
