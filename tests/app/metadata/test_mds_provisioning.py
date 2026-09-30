"""Runtime provisioning of the untracked FIDO MDS snapshot files."""

from __future__ import annotations

import gzip
import sys

import pytest

from server.app import mds_provisioning as provisioning
from server.app.mds import files as mds_files
from server.app.mds import sets as snapshot_sets
from tests.app.metadata.snapshot_versions import snapshot_version
from tests.app.storage import fake_gcs


@pytest.fixture
def static_root(monkeypatch, tmp_path):
    """Point provisioning at an empty static directory and reset its state."""

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    monkeypatch.setattr(
        provisioning, "_provision_state", {"attempted": False, "source": None}
    )
    return tmp_path


@pytest.fixture
def gcs(monkeypatch):
    """Cloud Storage on, as an in-memory bucket."""

    monkeypatch.delenv("FIDO_SERVER_MDS_GCS_PREFIX", raising=False)
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    return fake_gcs.install(monkeypatch)


def _local(static_root):
    return {name: (static_root / name).read_bytes() for name in provisioning.SNAPSHOT_FILENAMES}


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


def test_a_new_instance_takes_the_set_the_pointer_names(static_root, gcs):
    for name, data in snapshot_version(7).items():
        gcs.put(f"mds/{name}", data)
    snapshot_sets.publish(snapshot_version(8))

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(8)


def test_without_a_pointer_the_flat_objects_are_downloaded(static_root, gcs):
    for name, data in snapshot_version(7).items():
        gcs.put(f"mds/{name}", data)

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


def test_a_set_that_is_not_the_one_named_falls_back_to_the_flat_objects(static_root, gcs):
    for name, data in snapshot_version(7).items():
        gcs.put(f"mds/{name}", data)
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    gcs.put(pointer["set"] + mds_files.VERIFIED, b"{}")

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


def test_provisioning_result_is_reused_within_a_process(static_root, gcs):
    snapshot_sets.publish(snapshot_version(8))

    assert provisioning.ensure_snapshot_available() == "gcs"
    downloads = len(gcs.download_options)
    assert provisioning.ensure_snapshot_available() == "gcs"
    assert len(gcs.download_options) == downloads


def test_snapshot_is_unavailable_without_cloud_storage_or_upstream(static_root, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"


def test_an_empty_bucket_falls_through_to_an_upstream_refresh_it_publishes(static_root, gcs, monkeypatch):
    from tools import update_mds_snapshot

    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")

    def _refresh(argv):
        for name, data in snapshot_version(9).items():
            mds_files.write_file(static_root / name, data)
        return 0

    monkeypatch.setattr(update_mds_snapshot, "main", _refresh)

    assert provisioning.ensure_snapshot_available() == "upstream"
    pointer, _generation = snapshot_sets.read_pointer()
    assert pointer["no"] == 9
    assert snapshot_sets.download_set(pointer) == snapshot_version(9)


def test_a_failed_upstream_refresh_leaves_the_snapshot_unavailable(static_root, gcs, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "1")
    monkeypatch.setattr(provisioning, "_refresh_from_upstream", lambda: False)

    assert provisioning.ensure_snapshot_available() == "unavailable"
    assert gcs.objects == {}


def test_a_cloud_storage_error_does_not_propagate(static_root, gcs, monkeypatch):
    for name in ("current.json", *provisioning.SNAPSHOT_FILENAMES):
        gcs.failing[f"mds/{name}"] = fake_gcs.ServiceUnavailable("bucket unreachable")
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
    monkeypatch.setattr(mds_files.gzip, "compress", lambda data, **kwargs: data + b"pad")

    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", b"z" * 4096)

    assert not (static_root / "fido-mds3.explorer.full.json.gz").exists()


def test_upstream_refresh_runs_the_packaged_updater(static_root, monkeypatch):
    from tools import update_mds_snapshot

    monkeypatch.setattr(update_mds_snapshot, "main", lambda argv: 0 if argv == [] else 2)
    assert provisioning._refresh_from_upstream() is True

    monkeypatch.setattr(update_mds_snapshot, "main", lambda argv: 1)
    assert provisioning._refresh_from_upstream() is False


def test_a_failing_updater_is_reported_rather_than_raised(static_root, monkeypatch):
    from tools import update_mds_snapshot

    def _raise(argv):
        raise RuntimeError("upstream is down")

    monkeypatch.setattr(update_mds_snapshot, "main", _raise)

    assert provisioning._refresh_from_upstream() is False


def test_upstream_refresh_reports_a_build_without_the_updater(static_root, monkeypatch):
    # Setting a sys.modules entry to None makes importing that name raise.
    monkeypatch.setitem(sys.modules, "tools", None)
    monkeypatch.setitem(sys.modules, "tools.update_mds_snapshot", None)
    monkeypatch.setitem(sys.modules, "update_mds_snapshot", None)

    assert provisioning._refresh_from_upstream() is False


def test_a_publish_is_skipped_when_cloud_storage_is_disabled(static_root, gcs, monkeypatch):
    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)
    for name, data in snapshot_version(9).items():
        (static_root / name).write_bytes(data)

    provisioning._publish_to_gcs()
    assert gcs.objects == {}


def test_a_publish_error_does_not_propagate(static_root, gcs, monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("bucket unreachable")

    monkeypatch.setattr(provisioning.cloud, "upload_bytes_if_generation", _raise)
    for name, data in snapshot_version(9).items():
        (static_root / name).write_bytes(data)

    provisioning._publish_to_gcs()
    assert gcs.objects == {}
