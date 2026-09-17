"""Runtime provisioning of the untracked FIDO MDS snapshot files."""

from __future__ import annotations

import gzip

import pytest

provisioning = pytest.importorskip("server.app.mds_provisioning")


@pytest.fixture
def static_root(monkeypatch, tmp_path):
    """Point provisioning at an empty static directory and reset its state."""

    monkeypatch.setattr(provisioning, "_FRONTEND_STATIC_ROOT", tmp_path, raising=False)
    monkeypatch.setattr(
        provisioning, "_provision_state", {"attempted": False, "source": None}, raising=False
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

    monkeypatch.setattr(provisioning.cloud_storage, "download_bytes", _fail)

    assert provisioning.ensure_snapshot_available() == "local"


def test_missing_files_are_downloaded_from_cloud_storage(static_root, monkeypatch):
    requested = []

    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        provisioning.cloud_storage,
        "download_bytes",
        lambda name: requested.append(name) or b'{"entries": []}',
    )

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert requested == [f"mds/{name}" for name in provisioning.SNAPSHOT_FILENAMES]
    assert provisioning.missing_snapshot_files() == ()


def test_provisioning_result_is_reused_within_a_process(static_root, monkeypatch):
    calls = []
    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        provisioning.cloud_storage,
        "download_bytes",
        lambda name: calls.append(name) or b"{}",
    )

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert provisioning.ensure_snapshot_available() == "gcs"
    assert len(calls) == len(provisioning.SNAPSHOT_FILENAMES)


def test_snapshot_is_unavailable_without_cloud_storage_or_upstream(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: False)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_a_cloud_storage_gap_falls_through_to_an_upstream_refresh(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setattr(provisioning.cloud_storage, "download_bytes", lambda name: None)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")

    published = []
    monkeypatch.setattr(provisioning, "_refresh_from_upstream", lambda: True)
    monkeypatch.setattr(provisioning, "_upload_to_gcs", lambda names: published.append(names))

    assert provisioning.ensure_snapshot_available() == "upstream"
    assert published == [provisioning.SNAPSHOT_FILENAMES]


def test_a_failed_upstream_refresh_leaves_the_snapshot_unavailable(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setattr(provisioning.cloud_storage, "download_bytes", lambda name: None)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")
    monkeypatch.setattr(provisioning, "_refresh_from_upstream", lambda: False)

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_a_cloud_storage_error_does_not_propagate(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)

    def _raise(name):
        raise RuntimeError("bucket unreachable")

    monkeypatch.setattr(provisioning.cloud_storage, "download_bytes", _raise)
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

    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: True)
    assert provisioning.upstream_refresh_enabled() is True

    monkeypatch.setattr(provisioning.cloud_storage, "gcs_enabled", lambda: False)
    assert provisioning.upstream_refresh_enabled() is False


def test_the_blob_prefix_is_configurable(monkeypatch):
    assert provisioning.snapshot_blob_name("blob.jwt") == "mds/blob.jwt"

    monkeypatch.setenv("FIDO_SERVER_MDS_GCS_PREFIX", "snapshots/fido")
    assert provisioning.snapshot_blob_name("blob.jwt") == "snapshots/fido/blob.jwt"
