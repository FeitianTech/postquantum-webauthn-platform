"""Snapshot sets and their pointer, against an in-memory bucket (fake_gcs)."""

from __future__ import annotations

import json
import threading

import pytest

from server.app.mds import files as mds_files
from server.app.mds import sets as snapshot_sets
from server.app.storage import cloud
from tests.app.metadata.snapshot_versions import snapshot_version
from tests.app.storage import fake_gcs


@pytest.fixture
def bucket(monkeypatch):
    monkeypatch.delenv(snapshot_sets.PREFIX_ENV, raising=False)
    return fake_gcs.install(monkeypatch)


def _pointer(bucket):
    return json.loads(bucket.objects["mds/current.json"][0])


def _sets(bucket):
    return {name.rsplit("/", 1)[0] + "/" for name in bucket.objects if name.startswith("mds/sets/")}


def test_a_publish_writes_a_complete_set_then_points_to_it(bucket):
    files = snapshot_version(8)

    result = snapshot_sets.publish(files)

    assert result.outcome == "published"
    pointer = _pointer(bucket)
    assert pointer == result.pointer
    assert pointer["format"] == 1 and pointer["no"] == 8 and pointer["previous"] is None
    assert pointer["set"].startswith("mds/sets/1/8-")
    assert snapshot_sets.download_set(pointer) == files
    # Every file created fresh, the metas after the payloads, the pointer last.
    generations = {name: bucket.objects[pointer["set"] + name][1] for name in files}
    assert sorted(generations, key=generations.get) == list(mds_files.WRITE_ORDER)
    assert bucket.objects["mds/current.json"][1] > max(generations.values())


def test_the_pointer_only_moves_forward(bucket):
    snapshot_sets.publish(snapshot_version(8))
    before = dict(bucket.objects)

    assert snapshot_sets.publish(snapshot_version(8)).outcome == "current"
    assert snapshot_sets.publish(snapshot_version(7)).outcome == "current"
    assert bucket.objects == before


def test_a_failure_halfway_through_a_set_leaves_the_current_set(bucket, monkeypatch):
    snapshot_sets.publish(snapshot_version(8))
    before = dict(bucket.objects)
    upload = cloud.upload_bytes_if_generation

    def _failing(name, data, **kwargs):
        if name.endswith(mds_files.EXPLORER_FULL):
            raise OSError("the bucket went away")
        return upload(name, data, **kwargs)

    monkeypatch.setattr(cloud, "upload_bytes_if_generation", _failing)
    with pytest.raises(OSError):
        snapshot_sets.publish(snapshot_version(9))

    assert bucket.objects == before


def test_a_pointer_of_another_format_is_not_replaced(bucket):
    bucket.put("mds/current.json", json.dumps({"format": 2, "set": "mds/sets/2/9-x/"}).encode())
    before = dict(bucket.objects)

    with pytest.raises(snapshot_sets.SnapshotSetError):
        snapshot_sets.publish(snapshot_version(9))
    assert bucket.objects == before


def test_the_writer_that_loses_the_pointer_deletes_its_set(bucket):
    snapshot_sets.publish(snapshot_version(7))
    results = {}

    # Another writer publishes between this one's read of the pointer and its write.
    def _other_writer(name):
        if name == "mds/current.json" and "other" not in results:
            results["other"] = None
            results["other"] = snapshot_sets.publish(snapshot_version(9))

    bucket.on_download.append(_other_writer)
    results["this"] = snapshot_sets.publish(snapshot_version(8))

    assert results["other"].outcome == "published"
    assert results["this"].outcome == "lost"
    assert results["this"].pointer["no"] == 9
    pointer = _pointer(bucket)
    assert pointer["no"] == 9
    assert not any(name.startswith("mds/sets/1/8-") for name in bucket.objects)
    assert snapshot_sets.download_set(pointer) == snapshot_version(9)


def test_writers_at_once_leave_one_pointer_to_one_complete_set(bucket):
    versions = {no: snapshot_version(no) for no in range(8, 14)}
    start = threading.Barrier(len(versions))
    outcomes = []

    def _publish(no):
        start.wait()
        outcomes.append(snapshot_sets.publish(versions[no]).outcome)

    threads = [threading.Thread(target=_publish, args=(no,)) for no in versions]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert "published" in outcomes
    pointer = _pointer(bucket)
    assert snapshot_sets.download_set(pointer) == snapshot_version(pointer["no"])
    # Nothing but the current set and the one it replaced; every loser's is gone.
    assert _sets(bucket) <= {pointer["set"], pointer["previous"]}
    assert pointer["set"] in _sets(bucket)


def test_a_publish_deletes_the_set_two_back(bucket):
    first = snapshot_sets.publish(snapshot_version(8)).pointer["set"]
    second = snapshot_sets.publish(snapshot_version(9)).pointer["set"]
    assert _sets(bucket) == {first, second}

    third = snapshot_sets.publish(snapshot_version(10)).pointer
    assert _sets(bucket) == {second, third["set"]}
    assert third["previous"] == second


def test_a_set_that_is_not_the_one_named_is_refused(bucket):
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    bucket.put(pointer["set"] + mds_files.EXPLORER_FULL, b"{}")
    with pytest.raises(snapshot_sets.SnapshotSetError, match="not the file"):
        snapshot_sets.download_set(pointer)

    del bucket.objects[pointer["set"] + mds_files.VERIFIED]
    with pytest.raises(snapshot_sets.SnapshotSetError, match="missing"):
        snapshot_sets.download_set(pointer)


def test_a_pointer_is_usable_only_in_this_format(bucket):
    pointer = snapshot_sets.publish(snapshot_version(8)).pointer
    assert snapshot_sets.usable(pointer)
    assert not snapshot_sets.usable({**pointer, "format": 2})
    assert not snapshot_sets.usable({**pointer, "files": {}})
    assert not snapshot_sets.usable(None)

    bucket.put("mds/current.json", b"not json")
    assert snapshot_sets.read_pointer() == (None, bucket.objects["mds/current.json"][1])
