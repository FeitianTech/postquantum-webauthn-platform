from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from fido2.attestation.base import InvalidSignature

import tools.update_mds_snapshot as updater
from server.app.mds import files as mds_files
from server.app.mds import sets as snapshot_sets
from server.app.storage import cloud
from tests.app.metadata import mds_fixture
from tests.app.metadata.snapshot_versions import snapshot_version
from tests.app.storage import fake_gcs


def test_metadata_trust_root_is_globalsign_r46():
    certificate = x509.load_der_x509_certificate(updater.FIDO_METADATA_TRUST_ROOT_CERT)

    assert certificate.subject.rfc4514_string() == "CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE"


@pytest.fixture
def isolated_mds_paths(monkeypatch, tmp_path):
    snapshot = tmp_path / "mds-snapshot"
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(snapshot))
    return snapshot


def _file(name):
    return mds_files.snapshot_file(name)


def test_module_import_inserts_repo_root_when_missing(monkeypatch):
    module_name = "_update_mds_snapshot_path_branch_test"
    module_file = Path(updater.__file__).resolve()
    repo_root = str(module_file.parents[1])

    monkeypatch.setattr(sys, "path", [p for p in sys.path if p != repo_root])

    spec = importlib.util.spec_from_file_location(module_name, module_file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert sys.path[0] == repo_root


def test_the_updater_imports_without_flask_in_a_fresh_interpreter():
    # In-process, an import of flask by a module another test already loaded
    # would go unseen; a fresh interpreter loads everything.
    repo_root = Path(updater.__file__).resolve().parents[1]
    code = "import sys, tools.update_mds_snapshot; print(sorted(m for m in sys.modules if m.split('.')[0] == 'flask'))"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": str(repo_root)},
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == "[]", result.stdout


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
    assert _file(mds_files.BLOB).read_bytes() == b"initial"

    target = tmp_path / "nested" / "payload.txt"
    assert updater._write_if_changed(target, "hello") is True
    assert target.read_text(encoding="utf-8") == "hello"
    assert updater._write_if_changed(target, "hello") is False
    assert updater._write_if_changed(target, b"world") is True
    assert target.read_bytes() == b"world"

    serialised_json = updater._serialise_json({"b": 2, "a": 1})
    assert serialised_json == '{\n  "a": 1,\n  "b": 2\n}\n'

    compact_json = updater._serialise_compact_json({"b": 2, "a": "é"})
    assert compact_json == '{"a":"é","b":2}\n'

    finalised = updater._finalise_base_full_snapshot(
        {"entries": [{"name": "a"}, {"name": "b"}], "meta": {"no": 5}}
    )
    assert finalised["entries"] == [{"name": "a"}, {"name": "b"}]
    assert finalised["meta"] == {
        "no": 5,
        "entryCount": 2,
        "baseEntryCount": 2,
        "customEntryCount": 0,
        "hasCustomEntries": False,
    }


def test_load_existing_cache_handles_missing_invalid_and_non_dict(isolated_mds_paths):
    assert updater._load_existing_cache() == {}

    _file(mds_files.VERIFIED_META).parent.mkdir(parents=True, exist_ok=True)
    _file(mds_files.VERIFIED_META).write_text("not-json", encoding="utf-8")
    assert updater._load_existing_cache() == {}

    _file(mds_files.VERIFIED_META).write_text("[1, 2, 3]", encoding="utf-8")
    assert updater._load_existing_cache() == {}

    _file(mds_files.VERIFIED_META).write_text('{"fetched_at": "x"}', encoding="utf-8")
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


def _payload_with_unmodelled_fields() -> dict:
    return {
        "legalHeader": "test",
        "no": 3,
        "nextUpdate": "2026-10-20",
        "entries": [
            {
                "aaguid": "0132d110-bf4e-4208-a403-ab4f5f12efe5",
                "timeOfLastStatusChange": "2026-09-01",
                "statusReports": [
                    {
                        "status": "FIDO_CERTIFIED_L1",
                        "effectiveDate": "2026-09-01",
                        "certificationProfiles": ["consumer"],
                        "sunsetDate": "2029-09-01",
                        "fipsRevision": 3,
                        "fipsPhysicalSecurityLevel": 2,
                        "notYetDefined": {"kept": True},
                    }
                ],
            }
        ],
    }


def test_the_verified_snapshot_is_the_payload_as_the_blob_has_it():
    payload = _payload_with_unmodelled_fields()
    blob, root = mds_fixture._signed_blob(payload)

    assert updater._build_verified_snapshot(blob, root) == payload


def test_the_verified_snapshot_is_checked_against_the_trust_root(monkeypatch):
    blob, _root = mds_fixture._signed_blob(_payload_with_unmodelled_fields())
    seen = {}

    def _verify_blob(blob, cert):
        seen["args"] = (blob, cert)
        raise ValueError("bad signature")

    monkeypatch.setattr(updater.mds_blob, "verify_blob", _verify_blob)
    with pytest.raises(ValueError, match="bad signature"):
        updater._build_verified_snapshot(blob)
    assert seen["args"] == (blob, updater.FIDO_METADATA_TRUST_ROOT_CERT)


def test_a_blob_signed_by_another_root_is_refused():
    blob, _root = mds_fixture._signed_blob(_payload_with_unmodelled_fields())

    with pytest.raises(InvalidSignature):
        updater._build_verified_snapshot(blob)


def test_build_verified_snapshot_and_snapshot_files(monkeypatch, isolated_mds_paths):
    verified = {"entries": [], "no": 1}

    monkeypatch.setattr(
        updater, "build_explorer_snapshot", lambda _verified, _cache: {"entries": [], "meta": {"kind": "e"}}
    )
    monkeypatch.setattr(
        updater, "build_bootstrap_snapshot", lambda _verified, _cache: {"entries": [{}], "meta": {}}
    )
    files = updater.snapshot_files(b"blob-data", verified, {"a": 1})
    assert tuple(files) == mds_files.SNAPSHOT_FILENAMES
    assert files["blob.jwt"] == b"blob-data"
    assert files["fido-mds3.verified.json.meta.json"] == b'{\n  "a": 1\n}\n'
    assert json.loads(files["fido-mds3.explorer.json.meta.json"]) == {"kind": "e"}
    assert json.loads(files["fido-mds3.explorer.full.json"])["meta"]["baseEntryCount"] == 1
    assert not any(_file(name).exists() for name in mds_files.SNAPSHOT_FILENAMES)


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
        lambda _verified, _cache: {"entries": [{"name": "demo"}], "meta": {"kind": "full"}},
    )

    first = updater.main()
    first_output = capsys.readouterr().out
    assert first == 0
    assert "Packaged metadata snapshot refreshed." in first_output

    assert _file(mds_files.BLOB).read_bytes() == b"same-blob"
    assert json.loads(_file(mds_files.VERIFIED).read_text(encoding="utf-8"))["no"] == 99
    assert json.loads(_file(mds_files.EXPLORER_META).read_text(encoding="utf-8")) == {"kind": "explorer"}
    expected_full_meta = {
        "kind": "full",
        "entryCount": 1,
        "baseEntryCount": 1,
        "customEntryCount": 0,
        "hasCustomEntries": False,
    }
    assert json.loads(_file(mds_files.EXPLORER_FULL_META).read_text(encoding="utf-8")) == expected_full_meta
    assert json.loads(_file(mds_files.EXPLORER_FULL).read_text(encoding="utf-8")) == {
        "entries": [{"name": "demo"}],
        "meta": expected_full_meta,
    }

    second = updater.main()
    second_output = capsys.readouterr().out
    assert second == 0
    assert "already up to date" in second_output


@pytest.fixture
def stubbed_refresh(monkeypatch, isolated_mds_paths):
    """A successful refresh with the network and snapshot builders stubbed out."""

    monkeypatch.setattr(
        updater,
        "_fetch_remote_blob",
        lambda: (b"a-blob", "Wed, 03 Apr 2026 00:00:00 GMT", '"etag"'),
    )
    monkeypatch.setattr(
        updater,
        "_build_verified_snapshot",
        lambda _blob: {"entries": [{"aaguid": "x"}], "no": 42, "nextUpdate": "2026-12-01"},
    )
    monkeypatch.setattr(
        updater,
        "build_explorer_snapshot",
        lambda _verified, _cache: {"entries": [], "meta": {"kind": "explorer"}},
    )
    monkeypatch.setattr(
        updater,
        "build_bootstrap_snapshot",
        lambda _verified, _cache: {"entries": [], "meta": {"kind": "full"}},
    )
    return isolated_mds_paths


def test_a_refresh_writes_each_file_whole_and_the_metas_last(stubbed_refresh, monkeypatch):
    written = []
    write_file = mds_files.write_file

    def _record(path, data):
        written.append(path.name)
        # Never the file itself: a temporary file, renamed over it.
        assert not path.with_name(path.name + ".partial").exists()
        write_file(path, data)

    monkeypatch.setattr(mds_files, "write_file", _record)

    assert updater.main([]) == 0
    assert written == list(mds_files.WRITE_ORDER)
    assert written[-3:] == list(mds_files.META_FILENAMES)
    assert sorted(written) == sorted(mds_files.SNAPSHOT_FILENAMES)
    assert not list(stubbed_refresh.glob("*.partial"))


def test_verify_only_checks_the_blob_without_writing_files(stubbed_refresh, capsys):
    assert updater.main(["--verify-only"]) == 0

    assert "no. 42" in capsys.readouterr().out
    assert not _file(mds_files.BLOB).exists()
    assert not _file(mds_files.VERIFIED).exists()


@pytest.fixture
def bucket(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_MDS_GCS_PREFIX", raising=False)
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    return fake_gcs.install(monkeypatch)


@pytest.mark.parametrize("flag", ["--publish", "--gcs-upload"])
def test_publish_points_the_bucket_at_the_verified_snapshot(stubbed_refresh, bucket, flag, capsys):
    assert updater.main([flag]) == 0

    pointer, _generation = snapshot_sets.read_pointer()
    assert pointer["no"] == 42
    files = snapshot_sets.download_set(pointer)
    assert files[mds_files.BLOB] == b"a-blob"
    assert files == {name: _file(name).read_bytes() for name in mds_files.SNAPSHOT_FILENAMES}
    assert f"Published snapshot no. 42 as {pointer['set']}." in capsys.readouterr().out

    # The next run finds it there and publishes nothing.
    before = dict(bucket.objects)
    assert updater.main(["--publish"]) == 0
    assert bucket.objects == before
    assert "already has snapshot no. 42" in capsys.readouterr().out


def test_publish_fails_loudly_when_cloud_storage_is_disabled(stubbed_refresh, monkeypatch, capsys):
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: False)

    assert updater.main(["--publish"]) == 1
    assert "Cloud Storage is disabled" in capsys.readouterr().out


def test_publish_reports_a_bucket_failure(stubbed_refresh, bucket, monkeypatch, capsys):
    def _unavailable(*_args, **_kwargs):
        raise OSError("bucket unavailable")

    monkeypatch.setattr(cloud, "upload_bytes_if_generation", _unavailable)

    assert updater.main(["--publish"]) == 1
    assert "Could not publish the snapshot to Cloud Storage: bucket unavailable" in capsys.readouterr().out
    assert bucket.objects == {}


def test_publish_takes_the_pointer_back_from_an_older_publisher(stubbed_refresh, bucket, capsys):
    snapshot_sets.publish(snapshot_version(6))
    fired = []

    # An older publisher's pointer lands between this run's read and its write.
    def _older_publisher(name):
        if name.endswith("current.json") and not fired:
            fired.append(name)
            snapshot_sets.publish(snapshot_version(7))

    bucket.on_download.append(_older_publisher)

    assert updater.main(["--publish"]) == 0
    assert fired
    pointer = snapshot_sets.read_pointer()[0]
    assert pointer["no"] == 42
    assert pointer["previous"].startswith("mds/sets/1/7-")


def _rate_limited(monkeypatch):
    import io
    import urllib.error

    attempts = []

    def _urlopen(request, timeout):
        attempts.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {"Retry-After": "0"}, io.BytesIO())

    monkeypatch.setattr(updater.urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(updater.time, "sleep", lambda _seconds: None)
    return attempts


def test_a_rate_limited_refresh_keeps_the_snapshot_and_the_bucket(isolated_mds_paths, bucket, monkeypatch, capsys):
    current = snapshot_version(7)
    for name, data in current.items():
        mds_files.write_file(_file(name), data)
    snapshot_sets.publish(current)
    before = dict(bucket.objects)
    attempts = _rate_limited(monkeypatch)

    assert updater.main(["--publish"]) == 1

    assert len(attempts) == updater.MDS_DOWNLOAD_MAX_ATTEMPTS
    assert "Failed to download metadata BLOB" in capsys.readouterr().out
    assert bucket.objects == before
    assert {name: _file(name).read_bytes() for name in current} == current


def test_a_blob_that_fails_verification_writes_and_publishes_nothing(isolated_mds_paths, bucket, monkeypatch, capsys):
    # Signed by the fixture's own root, not the pinned FIDO Alliance one.
    blob, _root = mds_fixture._signed_blob(_payload_with_unmodelled_fields())
    monkeypatch.setattr(updater, "_fetch_remote_blob", lambda: (blob, None, '"etag"'))

    assert updater.main(["--publish"]) == 1

    assert "failed verification; nothing written" in capsys.readouterr().out
    assert bucket.objects == {}
    assert not isolated_mds_paths.exists() or not any(isolated_mds_paths.iterdir())
