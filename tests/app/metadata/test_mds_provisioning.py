"""Runtime provisioning of the untracked FIDO MDS snapshot files."""

from __future__ import annotations

import gzip
import sys

import pytest

provisioning = pytest.importorskip("server.app.mds_provisioning")


@pytest.fixture
def static_root(monkeypatch, tmp_path):
    """Point provisioning at an empty static directory and reset its state."""

    monkeypatch.setattr(provisioning, "_FRONTEND_STATIC_ROOT", tmp_path)
    monkeypatch.setattr(
        provisioning, "_provision_state", {"attempted": False, "source": None}
    )
    return tmp_path


def _write_all(static_root, payload=b"{}"):
    for name in provisioning.SNAPSHOT_FILENAMES:
        (static_root / name).write_bytes(payload)


def test_missing_snapshot_files_lists_everything_when_empty(static_root):
    assert provisioning.missing_snapshot_files() == provisioning.SNAPSHOT_FILENAMES


def test_missing_snapshot_files_is_empty_once_present(static_root):
    _write_all(static_root)

    assert provisioning.missing_snapshot_files() == ()


def test_local_files_are_used_without_touching_cloud_storage(static_root, monkeypatch):
    _write_all(static_root)

    def _fail(*args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("Cloud Storage must not be consulted for local files.")

    monkeypatch.setattr(provisioning.cloud, "download_bytes", _fail)

    assert provisioning.ensure_snapshot_available() == "local"


def test_missing_files_are_downloaded_from_cloud_storage(static_root, monkeypatch):
    requested = []

    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        provisioning.cloud,
        "download_bytes",
        lambda name: requested.append(name) or b'{"entries": []}',
    )

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert requested == [f"mds/{name}" for name in provisioning.SNAPSHOT_FILENAMES]
    assert provisioning.missing_snapshot_files() == ()


def test_provisioning_result_is_reused_within_a_process(static_root, monkeypatch):
    calls = []
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        provisioning.cloud,
        "download_bytes",
        lambda name: calls.append(name) or b"{}",
    )

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert provisioning.ensure_snapshot_available() == "gcs"
    assert len(calls) == len(provisioning.SNAPSHOT_FILENAMES)


def test_snapshot_is_unavailable_without_cloud_storage_or_upstream(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_a_cloud_storage_gap_falls_through_to_an_upstream_refresh(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(provisioning.cloud, "download_bytes", lambda name: None)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")

    published = []
    monkeypatch.setattr(provisioning, "_refresh_from_upstream", lambda: True)
    monkeypatch.setattr(provisioning, "_upload_to_gcs", lambda names: published.append(names))

    assert provisioning.ensure_snapshot_available() == "upstream"
    assert published == [provisioning.SNAPSHOT_FILENAMES]


def test_a_failed_upstream_refresh_leaves_the_snapshot_unavailable(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(provisioning.cloud, "download_bytes", lambda name: None)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")
    monkeypatch.setattr(provisioning, "_refresh_from_upstream", lambda: False)

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_a_cloud_storage_error_does_not_propagate(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)

    def _raise(name):
        raise RuntimeError("bucket unreachable")

    monkeypatch.setattr(provisioning.cloud, "download_bytes", _raise)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_the_browser_facing_snapshot_gets_a_precompressed_sibling(static_root):
    payload = b'{"entries": []}' + b" " * 4096

    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", payload)

    gzip_path = static_root / "fido-mds3.explorer.full.json.gz"
    assert gzip.decompress(gzip_path.read_bytes()) == payload


def test_server_only_snapshot_files_are_not_precompressed(static_root):
    provisioning.write_snapshot_file("blob.jwt", b"x" * 4096)

    assert not (static_root / "blob.jwt.gz").exists()


def test_no_partial_files_are_left_behind(static_root):
    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", b"y" * 4096)

    assert [path.name for path in static_root.glob("*.partial")] == []


def test_upstream_refresh_defaults_to_the_cloud_storage_setting(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", raising=False)

    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    assert provisioning.upstream_refresh_enabled() is True

    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)
    assert provisioning.upstream_refresh_enabled() is False


def test_the_blob_prefix_is_configurable(monkeypatch, app_config):
    assert provisioning.snapshot_blob_name("blob.jwt") == "mds/blob.jwt"

    monkeypatch.setenv("FIDO_SERVER_MDS_GCS_PREFIX", "snapshots/fido")
    assert provisioning.snapshot_blob_name("blob.jwt") == "snapshots/fido/blob.jwt"


def test_an_incompressible_payload_gets_no_gzip_sibling(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.gzip, "compress", lambda data, **kwargs: data + b"pad")

    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", b"z" * 4096)

    assert not (static_root / "fido-mds3.explorer.full.json.gz").exists()


def test_upstream_refresh_runs_the_packaged_updater(static_root, monkeypatch):
    from tools import update_mds_snapshot

    monkeypatch.setattr(update_mds_snapshot, "main", lambda: 0)
    assert provisioning._refresh_from_upstream() is True

    monkeypatch.setattr(update_mds_snapshot, "main", lambda: 1)
    assert provisioning._refresh_from_upstream() is False


def test_a_failing_updater_is_reported_rather_than_raised(static_root, monkeypatch):
    from tools import update_mds_snapshot

    def _raise():
        raise RuntimeError("upstream is down")

    monkeypatch.setattr(update_mds_snapshot, "main", _raise)

    assert provisioning._refresh_from_upstream() is False


def test_upstream_refresh_reports_a_build_without_the_updater(static_root, monkeypatch):
    # Setting a sys.modules entry to None makes importing that name raise.
    monkeypatch.setitem(sys.modules, "tools", None)
    monkeypatch.setitem(sys.modules, "tools.update_mds_snapshot", None)
    monkeypatch.setitem(sys.modules, "update_mds_snapshot", None)

    assert provisioning._refresh_from_upstream() is False


def test_upload_publishes_only_the_files_that_exist(static_root, monkeypatch):
    uploaded = []
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        provisioning.cloud,
        "upload_bytes",
        lambda name, data, content_type=None: uploaded.append((name, content_type)),
    )
    (static_root / "blob.jwt").write_bytes(b"blob")
    (static_root / "fido-mds3.verified.json").write_bytes(b"{}")

    provisioning._upload_to_gcs(provisioning.SNAPSHOT_FILENAMES)

    assert uploaded == [
        ("mds/blob.jwt", None),
        ("mds/fido-mds3.verified.json", "application/json"),
    ]


def test_upload_is_skipped_when_cloud_storage_is_disabled(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)

    def _fail(*args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("Nothing may be uploaded with Cloud Storage disabled.")

    monkeypatch.setattr(provisioning.cloud, "upload_bytes", _fail)
    (static_root / "blob.jwt").write_bytes(b"blob")

    provisioning._upload_to_gcs(provisioning.SNAPSHOT_FILENAMES)


def test_an_upload_error_does_not_propagate(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)

    def _raise(name, data, content_type=None):
        raise RuntimeError("bucket unreachable")

    monkeypatch.setattr(provisioning.cloud, "upload_bytes", _raise)
    (static_root / "blob.jwt").write_bytes(b"blob")

    provisioning._upload_to_gcs(provisioning.SNAPSHOT_FILENAMES)
