"""``read_for_update`` / ``save_if_unchanged``: compare-and-swap on the credential store.

Locally the check and the write happen under an ``flock`` on the file's
``.lock`` file, so the race is refereed across threads and across processes --
the server runs several gunicorn workers. On GCS the write carries an object
generation precondition. Either way exactly one of several writers that read
the same version wins, and the others write nothing.
"""
from __future__ import annotations

import multiprocessing
import os
import threading

import pytest

from server.app.storage import credentials as store

from . import fake_gcs

SESSION = "session-cas"
NAME = "alice@example.com"


@pytest.fixture
def local_store(monkeypatch, tmp_path):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(store, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(store, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(store, "basepath", str(tmp_path / "flat"))
    store.savekey(NAME, [{"sign_count": 5}], session_id=SESSION)
    return tmp_path


def test_a_save_after_an_unchanged_read_is_written(local_store):
    records, version = store.read_for_update(NAME, session_id=SESSION)
    records[0]["sign_count"] = 6

    assert store.save_if_unchanged(NAME, records, version, session_id=SESSION) is True
    assert store.readkey(NAME, session_id=SESSION) == [{"sign_count": 6}]


def test_a_save_after_someone_else_wrote_is_refused_and_writes_nothing(local_store):
    records, version = store.read_for_update(NAME, session_id=SESSION)
    store.savekey(NAME, [{"sign_count": 9}], session_id=SESSION)
    records[0]["sign_count"] = 6

    assert store.save_if_unchanged(NAME, records, version, session_id=SESSION) is False
    assert store.readkey(NAME, session_id=SESSION) == [{"sign_count": 9}]


def test_a_first_save_expects_no_file(local_store):
    records, version = store.read_for_update("new@example.com", session_id=SESSION)

    assert (records, version) == ([], None)
    assert store.save_if_unchanged("new@example.com", [{"sign_count": 1}], None, session_id=SESSION) is True
    assert store.save_if_unchanged("new@example.com", [{"sign_count": 2}], None, session_id=SESSION) is False


def test_of_eight_threads_that_read_the_same_version_one_writes(local_store):
    barrier = threading.Barrier(8, timeout=10)
    outcomes: list[bool] = []

    def _race(value):
        records, version = store.read_for_update(NAME, session_id=SESSION)
        barrier.wait()
        records[0]["sign_count"] = value
        outcomes.append(store.save_if_unchanged(NAME, records, version, session_id=SESSION))

    threads = [threading.Thread(target=_race, args=(100 + index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert sorted(outcomes) == [False] * 7 + [True]
    (winner,) = store.readkey(NAME, session_id=SESSION)
    assert 100 <= winner["sign_count"] < 108


def _race_in_a_process(root, value, barrier, results):
    os.environ.pop("FIDO_SERVER_GCS_ENABLED", None)
    from server.app.storage import credentials as child_store

    child_store._LOCAL_CREDENTIAL_BASE = os.path.join(root, "credentials")
    child_store._LEGACY_LOCAL_CREDENTIAL_BASE = os.path.join(root, "legacy")
    child_store.basepath = os.path.join(root, "flat")
    records, version = child_store.read_for_update(NAME, session_id=SESSION)
    barrier.wait()
    records[0]["sign_count"] = value
    results.put(child_store.save_if_unchanged(NAME, records, version, session_id=SESSION))


def test_of_three_processes_that_read_the_same_version_one_writes(local_store):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3, timeout=60)
    results = context.Queue()
    processes = [
        context.Process(target=_race_in_a_process, args=(str(local_store), 200 + index, barrier, results))
        for index in range(3)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=120)

    assert [process.exitcode for process in processes] == [0, 0, 0]
    assert sorted(results.get(timeout=10) for _ in processes) == [False, False, True]
    (winner,) = store.readkey(NAME, session_id=SESSION)
    assert 200 <= winner["sign_count"] < 203


# -- GCS: an object generation precondition ----------------------------------


@pytest.fixture
def gcs_store(monkeypatch):
    bucket = fake_gcs.install(monkeypatch, store)
    store.savekey(NAME, [{"sign_count": 5}], session_id=SESSION)
    return bucket


def test_gcs_refuses_the_second_of_two_writers_that_read_the_same_generation(gcs_store):
    first, first_version = store.read_for_update(NAME, session_id=SESSION)
    second, second_version = store.read_for_update(NAME, session_id=SESSION)
    first[0]["sign_count"] = second[0]["sign_count"] = 6

    assert first_version == second_version == 1
    assert store.save_if_unchanged(NAME, first, first_version, session_id=SESSION) is True
    assert store.save_if_unchanged(NAME, second, second_version, session_id=SESSION) is False
    assert store.readkey(NAME, session_id=SESSION) == [{"sign_count": 6}]


def test_gcs_expects_no_object_for_a_first_save(gcs_store):
    records, version = store.read_for_update("new@example.com", session_id=SESSION)

    assert (records, version) == ([], 0)
    assert store.save_if_unchanged("new@example.com", [{"sign_count": 1}], 0, session_id=SESSION) is True
    assert store.save_if_unchanged("new@example.com", [{"sign_count": 2}], 0, session_id=SESSION) is False


def test_a_conditional_gcs_upload_is_not_retried_by_the_client_library(gcs_store):
    # A retried conditional upload whose first attempt landed would fail its own
    # precondition and be mistaken for a lost race.
    records, version = store.read_for_update(NAME, session_id=SESSION)
    store.save_if_unchanged(NAME, records, version, session_id=SESSION)

    assert gcs_store.upload_retries[-1] is None


def test_a_delete_during_a_save_waits_for_it_and_leaves_no_records(local_store, monkeypatch):
    # The save is paused inside the store's lock, between its check and its
    # rename. A delete that did not take the lock would remove the file there,
    # and the rename would then write the deleted records back.
    records, version = store.read_for_update(NAME, session_id=SESSION)
    path = store._local_filename(NAME, SESSION)
    renaming, release = threading.Event(), threading.Event()
    real_replace = os.replace

    def _paused_replace(source, destination, *args, **kwargs):
        if destination == path and threading.current_thread().name == "saver":
            renaming.set()
            release.wait(10)
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", _paused_replace)
    saved = []
    saver = threading.Thread(
        name="saver",
        target=lambda: saved.append(store.save_if_unchanged(NAME, records + [{"sign_count": 6}], version, session_id=SESSION)),
    )
    saver.start()
    assert renaming.wait(10)
    deleter = threading.Thread(target=lambda: store.delkey(NAME, session_id=SESSION))
    deleter.start()
    deleter.join(0.5)
    release.set()
    saver.join(10)
    deleter.join(10)

    assert saved == [True]
    # Emptied, not removed: see delkey.
    with open(path, "rb") as handle:
        assert store.record_format.decode_payload(handle.read()) == []
    assert store.readkey(NAME, session_id=SESSION) == []


def test_deleting_a_name_with_nothing_stored_leaves_no_lock_file(local_store):
    store.delkey("nobody@example.com", session_id=SESSION)

    assert not os.path.exists(store._local_filename("nobody@example.com", SESSION) + ".lock")
