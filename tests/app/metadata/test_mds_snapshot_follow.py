"""A running instance takes the newer snapshot set the bucket's pointer names.

An instance keeps the snapshot it started with unless it asks: the MDS info
route (where the page starts) reads the pointer at most once per interval, and
the one request that finds a newer set takes it while the others go on.
"""

from __future__ import annotations

import json
import threading

import pytest

from server.app.mds import files as mds_files
from server.app.mds import provisioning as mds_provisioning
from server.app.mds import sets as snapshot_sets
from tests.app.metadata.snapshot_versions import snapshot_version
from tests.app.storage import fake_gcs


@pytest.fixture
def instance(monkeypatch, tmp_path, metadata_state, fixture_blob_root):
    """A running instance with snapshot no. 7, and Cloud Storage as an in-memory bucket."""

    directory = tmp_path / "mds-snapshot"
    for name in mds_files.WRITE_ORDER:
        mds_files.write_file(directory / name, snapshot_version(7)[name])
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(directory))
    monkeypatch.delenv("FIDO_SERVER_MDS_GCS_PREFIX", raising=False)
    monkeypatch.setenv("FIDO_SERVER_MDS_POINTER_CHECK_SECONDS", "0")
    monkeypatch.setattr(mds_provisioning, "_provision_state", {"attempted": True, "source": "local"})
    monkeypatch.setattr(mds_provisioning, "_follow_state", {"checked_at": None})
    monkeypatch.setattr(mds_provisioning, "_follow_lock", threading.Lock())
    monkeypatch.setattr(mds_provisioning.cloud, "gcs_enabled", lambda: True)
    bucket = fake_gcs.install(monkeypatch)
    return directory, bucket


def _local(directory):
    return {name: (directory / name).read_bytes() for name in mds_files.SNAPSHOT_FILENAMES}


def _info(client):
    info = client.get("/api/mds/metadata/info").get_json()
    return info["no"], info["snapshotUrl"]


def test_a_newer_set_in_the_bucket_reaches_a_running_instance(instance, client):
    directory, bucket = instance
    no, url = _info(client)
    assert no == 7 and json.loads(client.get(url).data)["meta"]["no"] == 7

    snapshot_sets.publish(snapshot_version(8))

    no, url = _info(client)
    assert no == 8
    assert _local(directory) == snapshot_version(8)
    with client.get(url, headers={"Accept-Encoding": "identity"}) as listed:
        assert listed.headers["Cache-Control"] == "no-cache"
        assert json.loads(listed.data)["meta"]["no"] == 8
    # The explorer's own rows follow too.
    rows = client.get("/api/mds/metadata/explorer/full").get_json()
    assert rows["meta"]["no"] == 8 and len(rows["entries"]) == 3
    # Taken from the set's BLOB and meta alone, the rest derived.
    taken = {name for name, _options in bucket.download_options if name.startswith("mds/sets/")}
    assert {name.rsplit("/", 1)[1] for name in taken} == {mds_files.BLOB, mds_files.VERIFIED_META}


def test_the_pointer_is_read_at_most_once_per_interval(instance, client, monkeypatch):
    directory, bucket = instance
    monkeypatch.setenv("FIDO_SERVER_MDS_POINTER_CHECK_SECONDS", "900")
    clock = [1000.0]
    monkeypatch.setattr(mds_provisioning.time, "monotonic", lambda: clock[0])

    _info(client)
    snapshot_sets.publish(snapshot_version(8))
    reads = len(bucket.download_options)

    clock[0] += 899
    assert _info(client)[0] == 7
    assert len(bucket.download_options) == reads

    clock[0] += 1
    assert _info(client)[0] == 8
    # One short read of the pointer, tried once, inside the request.
    assert bucket.download_options[reads] == ("mds/current.json", {"timeout": 5.0, "retry": None})


def test_an_older_or_the_same_set_is_left_alone(instance, client):
    directory, bucket = instance
    snapshot_sets.publish(snapshot_version(6))
    assert _info(client)[0] == 7
    assert _local(directory) == snapshot_version(7)


def test_other_requests_go_on_while_one_takes_the_new_set(instance, client, app):
    directory, bucket = instance
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    downloading = threading.Event()
    release = threading.Event()

    def _slow(name):
        if name.startswith(pointer["set"]):
            downloading.set()
            release.wait(10)

    bucket.on_download.append(_slow)
    taking = threading.Thread(target=lambda: app.test_client().get("/api/mds/metadata/info"), daemon=True)
    taking.start()
    try:
        assert downloading.wait(5)
        # Not held: it answers from the snapshot it has.
        assert _info(client)[0] == 7
    finally:
        release.set()
        taking.join(10)
    assert _info(client)[0] == 8


@pytest.mark.parametrize(
    "failure", ["a file not the one named", "the bucket unreachable", "a file gone", "a BLOB of another snapshot"]
)
def test_a_failed_follow_keeps_the_snapshot(instance, client, failure):
    directory, bucket = instance
    if failure == "a BLOB of another snapshot":
        snapshot_sets.publish({**snapshot_version(8), mds_files.BLOB: snapshot_version(9)[mds_files.BLOB]})
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    if failure == "a file not the one named":
        bucket.put(pointer["set"] + mds_files.BLOB, b"{}")
    elif failure == "the bucket unreachable":
        bucket.failing["mds/current.json"] = fake_gcs.ServiceUnavailable("unreachable")
    elif failure == "a file gone":
        del bucket.objects[pointer["set"] + mds_files.VERIFIED_META]

    no, url = _info(client)
    assert no == 7 and json.loads(client.get(url).data)["meta"]["no"] == 7
    assert _local(directory) == snapshot_version(7)
    assert not list(directory.glob("*.partial"))


def test_a_set_pruned_under_a_following_instance_is_taken_on_the_next_check(instance, client):
    directory, bucket = instance
    snapshot_sets.publish(snapshot_version(8))
    raced = []

    # Once this instance has read the pointer to no. 8, two more publishes land
    # before it fetches the set: no. 10 deletes no. 8, two back, under it.
    def _publishers(name):
        if name == "mds/current.json" and not raced:
            raced.append(name)
            snapshot_sets.publish(snapshot_version(9))
            snapshot_sets.publish(snapshot_version(10))

    bucket.on_download.append(_publishers)

    assert _info(client)[0] == 7
    assert _local(directory) == snapshot_version(7)
    assert _info(client)[0] == 10
    assert _local(directory) == snapshot_version(10)


def test_without_cloud_storage_nothing_is_asked(instance, client, monkeypatch):
    directory, bucket = instance
    monkeypatch.setattr(mds_provisioning.cloud, "gcs_enabled", lambda: False)
    snapshot_sets.publish(snapshot_version(8))
    reads = len(bucket.download_options)

    assert _info(client)[0] == 7
    assert len(bucket.download_options) == reads


@pytest.mark.parametrize("local_meta", [None, b"not-json", b"[]", b'{"no":"7"}'])
def test_a_follow_replaces_a_snapshot_whose_local_serial_cannot_be_read(instance, client, local_meta):
    directory, _bucket = instance
    meta = directory / mds_files.VERIFIED_META
    if local_meta is None:
        meta.unlink()
    else:
        meta.write_bytes(local_meta)
    snapshot_sets.publish(snapshot_version(8))

    assert _info(client)[0] == 8
    assert _local(directory) == snapshot_version(8)
