"""Runtime provisioning of the untracked FIDO MDS snapshot files."""

from __future__ import annotations

import base64
import builtins
import json
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.utils import websafe_encode

from server.app.mds import files as mds_files
from server.app.mds import provisioning
from server.app.mds import sets as snapshot_sets
from server.app.mds import snapshot as mds_snapshot
from tests.app.metadata.snapshot_versions import snapshot_version
from tests.app.storage import fake_gcs
from tools import update_mds_snapshot


@pytest.fixture
def static_root(monkeypatch, tmp_path):
    """Point provisioning at an empty static directory and reset its state."""

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    monkeypatch.setattr(
        provisioning, "_provision_state", {"attempted": False, "source": None}
    )
    return tmp_path


@pytest.fixture
def gcs(monkeypatch, fixture_blob_root):
    """Cloud Storage on, as an in-memory bucket, holding snapshots signed by the fixture's root."""

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


def test_without_a_pointer_the_flat_blob_and_meta_are_taken_and_the_rest_derived(static_root, gcs):
    for name, data in snapshot_version(7).items():
        gcs.put(f"mds/{name}", data)

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)
    fetched = {name for name, _options in gcs.download_options}
    assert fetched == {snapshot_sets.pointer_name(), f"mds/{mds_files.BLOB}", f"mds/{mds_files.VERIFIED_META}"}


def test_the_flat_snapshot_replaces_an_older_partial_one_whole(static_root, gcs):
    _flat(gcs, 7)
    (static_root / mds_files.VERIFIED_META).write_bytes(snapshot_version(6)[mds_files.VERIFIED_META])
    (static_root / mds_files.BLOB).write_bytes(b"a file of another snapshot")

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


def test_a_flat_snapshot_older_than_the_local_one_is_not_taken(static_root, gcs, monkeypatch):
    _flat(gcs, 7)
    (static_root / mds_files.VERIFIED_META).write_bytes(snapshot_version(8)[mds_files.VERIFIED_META])
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"
    assert provisioning.missing_snapshot_files() == tuple(
        name for name in provisioning.SNAPSHOT_FILENAMES if name != mds_files.VERIFIED_META
    )


@pytest.mark.parametrize("broken", ["blob of another snapshot", "meta missing", "blob missing"])
def test_a_flat_snapshot_that_does_not_verify_is_not_taken(static_root, gcs, monkeypatch, broken):
    _flat(gcs, 7)
    if broken == "blob of another snapshot":
        gcs.put(f"mds/{mds_files.BLOB}", snapshot_version(8)[mds_files.BLOB])
    else:
        del gcs.objects[f"mds/{mds_files.VERIFIED_META if broken == 'meta missing' else mds_files.BLOB}"]
    monkeypatch.setenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", "0")

    assert provisioning.ensure_snapshot_available() == "unavailable"
    assert provisioning.missing_snapshot_files() == provisioning.SNAPSHOT_FILENAMES


def _flat(gcs, no=7):
    for name, data in snapshot_version(no).items():
        gcs.put(f"mds/{name}", data)


def _repoint(gcs, **changes):
    pointer, _generation = snapshot_sets.read_pointer()
    gcs.put(snapshot_sets.pointer_name(), json.dumps({**pointer, **changes}).encode())


def test_a_new_instance_fetches_the_sets_blob_and_meta_alone_and_derives_the_rest(static_root, gcs):
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(8)
    fetched = {name for name, _options in gcs.download_options}
    assert fetched == {snapshot_sets.pointer_name(), pointer["set"] + mds_files.BLOB, pointer["set"] + mds_files.VERIFIED_META}


@pytest.mark.parametrize("broken", ["blob replaced", "meta missing"])
def test_a_set_that_is_not_the_one_named_falls_back_to_the_flat_objects(static_root, gcs, broken):
    _flat(gcs)
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    if broken == "blob replaced":
        gcs.put(pointer["set"] + mds_files.BLOB, snapshot_version(9)[mds_files.BLOB])
    else:
        del gcs.objects[pointer["set"] + mds_files.VERIFIED_META]

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


def test_a_set_whose_blob_another_key_signed_is_refused(static_root, gcs, monkeypatch):
    _flat(gcs)
    snapshot_sets.publish(snapshot_version(8))
    # Pinned now: another root, so the set's BLOB, named by the pointer as it is, does not verify.
    monkeypatch.setattr(provisioning.mds_snapshot.mds_trust, "FIDO_METADATA_TRUST_ROOT_CERT", _expiring_root()[1])

    assert provisioning._download_set_from_gcs() is None
    assert provisioning.missing_snapshot_files() == provisioning.SNAPSHOT_FILENAMES


def test_a_set_whose_blob_is_another_snapshot_than_its_meta_is_refused(static_root, gcs):
    _flat(gcs)
    files = {**snapshot_version(8), mds_files.BLOB: snapshot_version(9)[mds_files.BLOB]}
    snapshot_sets.publish(files)

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


@pytest.mark.parametrize("change", [{"no": 9}, {"files": "the payload's digest"}])
def test_a_set_that_is_not_the_snapshot_its_pointer_says_is_refused(static_root, gcs, change):
    _flat(gcs)
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    if "files" in change:
        files = json.loads(json.dumps(pointer["files"]))
        files[mds_files.VERIFIED]["sha256"] = "0" * 64
        change = {"files": files}
    _repoint(gcs, **change)

    assert provisioning.ensure_snapshot_available() == "gcs"
    assert _local(static_root) == snapshot_version(7)


def _expiring_root() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """A root that was valid from January to the end of September 2026."""

    key = ec.derive_private_key(0x5EED, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Expired MDS BLOB Signer")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2026, 9, 30, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize(("fetched_at", "taken"), [("2026-09-20T08:00:00+00:00", True), ("2026-10-02T08:00:00+00:00", False)])
def test_a_blob_is_checked_at_the_time_it_was_fetched(static_root, gcs, monkeypatch, fetched_at, taken):
    key, root = _expiring_root()
    monkeypatch.setattr(provisioning.mds_snapshot.mds_trust, "FIDO_METADATA_TRUST_ROOT_CERT", root)
    version = snapshot_version(8)
    payload = json.loads(version[mds_files.VERIFIED])
    cache_state = {**json.loads(version[mds_files.VERIFIED_META]), "fetched_at": fetched_at}
    header = {"alg": "ES256", "x5c": [base64.b64encode(root).decode("ascii")]}
    message = b".".join(websafe_encode(json.dumps(part).encode()).encode("ascii") for part in (header, payload))
    blob = message + b"." + websafe_encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).encode("ascii")
    snapshot_sets.publish(mds_snapshot.snapshot_files(blob, payload, cache_state))

    assert (provisioning._download_set_from_gcs() is not None) is taken


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


def test_a_snapshot_file_is_written_whole_and_alone(static_root):
    payload = b'{"entries": []}' + b" " * 4096

    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", payload)

    assert (static_root / "fido-mds3.explorer.full.json").read_bytes() == payload
    # Browsers load the explorer's files the server derives: no .gz copy beside it.
    assert [path.name for path in static_root.iterdir()] == ["fido-mds3.explorer.full.json"]


def test_no_partial_files_are_left_behind(static_root):
    provisioning.write_snapshot_file("fido-mds3.explorer.full.json", b"y" * 4096)

    assert [path.name for path in static_root.glob("*.partial")] == []


def test_upstream_refresh_defaults_to_the_cloud_storage_setting(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_MDS_FETCH_UPSTREAM", raising=False)

    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: True)
    assert provisioning.upstream_refresh_enabled() is True

    monkeypatch.setattr(provisioning.cloud, "gcs_enabled", lambda: False)
    assert provisioning.upstream_refresh_enabled() is False


def test_the_blob_prefix_is_configurable(monkeypatch):
    assert provisioning.snapshot_blob_name("blob.jwt") == "mds/blob.jwt"

    monkeypatch.setenv("FIDO_SERVER_MDS_GCS_PREFIX", "snapshots/fido")
    assert provisioning.snapshot_blob_name("blob.jwt") == "snapshots/fido/blob.jwt"


def test_upstream_refresh_runs_the_packaged_updater(static_root, monkeypatch):
    monkeypatch.setattr(update_mds_snapshot, "main", lambda argv: 0 if argv == [] else 2)
    assert provisioning._refresh_from_upstream() is True

    monkeypatch.setattr(update_mds_snapshot, "main", lambda argv: 1)
    assert provisioning._refresh_from_upstream() is False


def test_a_failing_updater_is_reported_rather_than_raised(static_root, monkeypatch):
    def _raise(argv):
        raise RuntimeError("upstream is down")

    monkeypatch.setattr(update_mds_snapshot, "main", _raise)

    assert provisioning._refresh_from_upstream() is False


def test_upstream_refresh_reports_a_build_without_the_updater(static_root, monkeypatch, caplog):
    # A build without tools/ cannot import the updater. Provisioning imports it
    # inside the refresh, where only the import machinery can make it fail, so
    # builtins.__import__ is patched; every other import goes through it unchanged.
    real_import = builtins.__import__

    def _without_tools(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tools" or name.startswith("tools."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _without_tools)

    assert provisioning._refresh_from_upstream() is False
    assert "updater is not packaged with this build" in caplog.text


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


@pytest.mark.parametrize(("setting", "seconds"), [("60", 60.0), ("15m", 900.0), ("-5", 0.0)])
def test_the_pointer_check_interval_is_seconds_or_its_default(monkeypatch, setting, seconds):
    monkeypatch.setenv("FIDO_SERVER_MDS_POINTER_CHECK_SECONDS", setting)

    assert provisioning._pointer_check_seconds() == seconds
