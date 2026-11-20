"""Tests for github_outbox: the credential log's queue, its bound, its lease and its flush."""
from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
import types

import pytest

from server.app.storage import common as storage_common
from server.app.storage import github_outbox
from server.app.storage.github_outbox import Delivery, OutboxEntry
from tests.app.storage import fake_gcs


def _entry(name: str, content: bytes = b"{}") -> OutboxEntry:
    return OutboxEntry("registration", f"logs/unknown/{name}.json", f"add: {name}.json (AAGUID=unknown)", content)


def _path(name: str) -> str:
    return f"logs/unknown/{name}.json"


# An entry as this server stored it before it counted attempts, queued before any made now.
_OLD_FORMAT = b'{"kind":"registration","path":"logs/unknown/old.json","message":"add: old.json (AAGUID=unknown)"}\n{}'
_OLD_ID = "20251101T000000000000Z-0123abcd"


def _attempts(outbox) -> dict[str, int]:
    return {entry.path: entry.attempts for entry in outbox.entries()}


class _Clock:
    """The outbox's time, moved by hand."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def time(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(github_outbox, "time", types.SimpleNamespace(time=clock.time))
    return clock


class _LocalView:
    """The local outbox as a test looks at it."""

    backend = github_outbox._LocalOutbox

    def __init__(self, root) -> None:
        self.root = root

    def names(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(name for name in os.listdir(self.root) if name.endswith(".entry"))

    def entries(self) -> list[OutboxEntry]:
        return [github_outbox.decode_entry((self.root / name).read_bytes()) for name in self.names()]

    def put(self, entry_id: str, data: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / f"{entry_id}.entry").write_bytes(data)

    def delete(self, name: str) -> None:
        (self.root / name).unlink()

    def is_empty(self) -> bool:
        return not self.root.exists()


class _CloudView:
    """The outbox in the fake bucket as a test looks at it."""

    backend = github_outbox._CloudOutbox

    def __init__(self, bucket) -> None:
        self.bucket = bucket

    def names(self) -> list[str]:
        return sorted(name for name in self.bucket.objects if name.startswith("github-outbox/entries/"))

    def entries(self) -> list[OutboxEntry]:
        return [github_outbox.decode_entry(self.bucket.objects[name][0]) for name in self.names()]

    def put(self, entry_id: str, data: bytes) -> None:
        self.bucket.put(f"github-outbox/entries/{entry_id}", data)

    def delete(self, name: str) -> None:
        del self.bucket.objects[name]

    def is_empty(self) -> bool:
        return not self.bucket.objects


def _local_view(monkeypatch, tmp_path) -> _LocalView:
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    root = tmp_path / "github-outbox"
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(root))
    return _LocalView(root)


@pytest.fixture(params=["local", "cloud"])
def outbox(request, monkeypatch, tmp_path):
    """The outbox on each backend: a folder of this test's, or a fake bucket."""

    if request.param == "local":
        return _local_view(monkeypatch, tmp_path)
    return _CloudView(fake_gcs.install(monkeypatch, "the outbox"))


@pytest.fixture
def local_outbox(monkeypatch, tmp_path):
    return _local_view(monkeypatch, tmp_path)


@pytest.fixture
def bucket_outbox(monkeypatch):
    return _CloudView(fake_gcs.install(monkeypatch, "the outbox"))


class _Deliverer:
    """A stand-in for the mirror's delivery: what it was given, and what it answers."""

    def __init__(self, answers: dict[str, Delivery] | None = None) -> None:
        self.paths: list[str] = []
        self.answers = answers or {}
        self.lock = threading.Lock()

    def __call__(self, entry: OutboxEntry) -> Delivery:
        with self.lock:
            self.paths.append(entry.path)
        return self.answers.get(entry.path, Delivery.DELIVERED)


def test_an_entry_reads_back_as_it_was_queued():
    entry = OutboxEntry("metadata", "metadata/ä b#1.json", "metadata: add ä b#1.json", b"line one\nline two\n\x00\xff")

    data = github_outbox.encode_entry(entry)

    assert data.startswith(b'{"kind":"metadata","path":"metadata/\\u00e4 b#1.json"')
    assert github_outbox.decode_entry(data) == entry


def test_an_entry_s_failed_attempts_are_kept_in_its_header():
    entry = _entry("one")._replace(attempts=3)

    data = github_outbox.encode_entry(entry)

    assert data.partition(b"\n")[0].endswith(b',"attempts":3}')
    assert github_outbox.decode_entry(data) == entry


def test_an_entry_queued_before_attempts_were_counted_reads_as_none():
    assert github_outbox.decode_entry(_OLD_FORMAT).attempts == 0


@pytest.mark.parametrize(
    "data",
    [
        b"no header line",
        b"not json\n{}",
        b"[1, 2]\n{}",
        b'{"kind": "registration", "path": "logs/x.json"}\n{}',
        b'{"kind": "registration", "path": 3, "message": "m"}\n{}',
        b'{"kind": "r\xc3\xa9", "path": "p", "message": "m"}\n{}',
        b'{"kind": "registration", "path": "p", "message": "m", "attempts": -1}\n{}',
        b'{"kind": "registration", "path": "p", "message": "m", "attempts": "2"}\n{}',
        b'{"kind": "registration", "path": "p", "message": "m", "attempts": 1.5}\n{}',
        b'{"kind": "registration", "path": "p", "message": "m", "attempts": true}\n{}',
    ],
)
def test_anything_else_is_not_an_entry(data):
    with pytest.raises(ValueError):
        github_outbox.decode_entry(data)


def test_queued_entries_are_delivered_oldest_first_and_removed(outbox):
    assert github_outbox.enqueue([_entry("one"), _entry("two")]) == 2
    assert github_outbox.enqueue([_entry("three")]) == 1
    deliverer = _Deliverer()

    run = github_outbox.flush(deliverer)

    assert run == github_outbox.FlushRun(3, 0.0)
    assert deliverer.paths == [f"logs/unknown/{name}.json" for name in ("one", "two", "three")]
    assert outbox.entries() == []


def test_the_outbox_folder_is_ignored_by_git_and_holds_only_entries_and_the_lease(local_outbox):
    outbox = local_outbox.root
    github_outbox.enqueue([_entry("one")])
    github_outbox.flush(_Deliverer({"logs/unknown/one.json": Delivery.UNAVAILABLE}))

    names = sorted(os.listdir(outbox))
    assert names[:2] == [".gitignore", ".lease"]
    assert len(names) == 3 and names[2].endswith(".entry")
    assert "*" in (outbox / ".gitignore").read_text().splitlines()


def test_nothing_queued_writes_nothing(outbox):
    assert github_outbox.enqueue([]) == 0
    assert outbox.is_empty()
    assert github_outbox.flush(_Deliverer()) == github_outbox.FlushRun(0, 0.0)
    # A run with nothing to deliver lists the outbox and takes no lease.
    assert outbox.is_empty()


def test_a_run_with_nothing_queued_leaves_the_lease_alone(bucket_outbox):
    github_outbox.enqueue([_entry("one")])
    github_outbox.flush(_Deliverer())
    bucket = bucket_outbox.bucket
    lease = bucket.objects["github-outbox/lease"]
    listings, downloads = len(bucket.list_calls), len(bucket.download_options)

    assert github_outbox.flush(_Deliverer()) == github_outbox.FlushRun(0, 0.0)

    assert bucket.objects["github-outbox/lease"] == lease
    assert len(bucket.list_calls) == listings + 1
    assert len(bucket.download_options) == downloads


def test_a_dropped_entry_is_removed_too(outbox):
    github_outbox.enqueue([_entry("one"), _entry("two")])

    run = github_outbox.flush(_Deliverer({"logs/unknown/one.json": Delivery.DROPPED}))

    assert run.handled == 2
    assert outbox.entries() == []


def test_a_run_delivers_at_most_its_limit(outbox):
    github_outbox.enqueue([_entry(f"e{index}") for index in range(5)])
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer, limit=2).handled == 2
    assert github_outbox.flush(deliverer, limit=2).handled == 2
    assert github_outbox.flush(deliverer, limit=2).handled == 1
    assert deliverer.paths == [f"logs/unknown/e{index}.json" for index in range(5)]


def test_entries_github_cannot_take_stay_and_every_flusher_backs_off(outbox, clock):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    refusing = _Deliverer({_path("one"): Delivery.UNAVAILABLE, _path("two"): Delivery.UNAVAILABLE})

    run = github_outbox.flush(refusing)

    assert run == github_outbox.FlushRun(0, clock.now + github_outbox.BACKOFF_SECONDS)
    assert refusing.paths == ["logs/unknown/one.json", "logs/unknown/two.json"]
    assert [entry.path for entry in outbox.entries()] == ["logs/unknown/one.json", "logs/unknown/two.json"]

    clock.now += github_outbox.BACKOFF_SECONDS - 1
    waiting = _Deliverer()
    assert github_outbox.flush(waiting) == run
    assert waiting.paths == []

    clock.now += 1
    assert github_outbox.flush(waiting).handled == 2
    assert outbox.entries() == []


def test_an_entry_github_never_takes_is_given_up_after_runs_that_delivered_a_later_one(outbox, clock, caplog):
    stuck = _path("stuck")
    github_outbox.enqueue([_entry("stuck"), _entry("later1")])
    deliverer = _Deliverer({stuck: Delivery.UNAVAILABLE})

    # GitHub took the entry behind it: the stuck one is counted, and nothing backs off.
    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(1, 0.0)
    assert _attempts(outbox) == {stuck: 1}

    # With nothing delivered after it, its failure is not counted, and the outbox backs off.
    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(0, clock.now + github_outbox.BACKOFF_SECONDS)
    assert _attempts(outbox) == {stuck: 1}
    clock.now += github_outbox.BACKOFF_SECONDS

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        for attempts in range(2, github_outbox.MAX_ATTEMPTS):
            github_outbox.enqueue([_entry(f"later{attempts}")])
            assert github_outbox.flush(deliverer) == github_outbox.FlushRun(1, 0.0)
            assert _attempts(outbox) == {stuck: attempts}
        assert "Dropped" not in caplog.text

        github_outbox.enqueue([_entry("last")])
        assert github_outbox.flush(deliverer) == github_outbox.FlushRun(2, 0.0)

    assert outbox.entries() == []
    assert [path for path in deliverer.paths if path != stuck] == [
        _path(name) for name in ["later1", *(f"later{n}" for n in range(2, github_outbox.MAX_ATTEMPTS)), "last"]
    ]
    assert (
        f"Dropped {stuck} from the credential log: GitHub did not take it in {github_outbox.MAX_ATTEMPTS} runs "
        "that delivered later entries"
    ) in caplog.text


def test_an_outage_counts_nothing_and_drops_nothing_however_many_runs(outbox, clock):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    queued = outbox.entries()
    down = _Deliverer({_path("one"): Delivery.UNAVAILABLE, _path("two"): Delivery.UNAVAILABLE})

    for _run in range(github_outbox.MAX_ATTEMPTS + 1):
        assert github_outbox.flush(down) == github_outbox.FlushRun(0, clock.now + github_outbox.BACKOFF_SECONDS)
        clock.now += github_outbox.BACKOFF_SECONDS

    assert outbox.entries() == queued
    assert _attempts(outbox) == {_path("one"): 0, _path("two"): 0}


def test_a_run_stops_after_a_few_entries_in_a_row_github_cannot_take(outbox, clock):
    in_a_row = [f"down{index}" for index in range(github_outbox.MAX_UNAVAILABLE_IN_A_ROW)]
    names = ["first", "taken", *in_a_row, "untried"]
    github_outbox.enqueue([_entry(name) for name in names])
    deliverer = _Deliverer({_path(name): Delivery.UNAVAILABLE for name in ["first", *in_a_row]})

    run = github_outbox.flush(deliverer)

    assert run == github_outbox.FlushRun(1, clock.now + github_outbox.BACKOFF_SECONDS)
    assert deliverer.paths == [_path(name) for name in names[:-1]]
    # Only the entry with a delivery after it is counted.
    assert _attempts(outbox) == {_path("first"): 1, **{_path(name): 0 for name in [*in_a_row, "untried"]}}


def test_an_entry_queued_before_attempts_were_counted_is_delivered_and_counted_from_none(outbox):
    outbox.put(_OLD_ID, _OLD_FORMAT)
    outbox.put(_OLD_ID.replace("0123abcd", "4567cdef"), _OLD_FORMAT.replace(b"old.json", b"older.json"))
    deliverer = _Deliverer({_path("old"): Delivery.UNAVAILABLE})

    assert github_outbox.flush(deliverer).handled == 1

    assert deliverer.paths == [_path("old"), _path("older")]
    assert _attempts(outbox) == {_path("old"): 1}

    assert github_outbox.flush(_Deliverer()).handled == 1
    assert outbox.entries() == []


def test_an_entry_s_attempts_are_read_from_the_outbox(outbox, caplog):
    almost = _OLD_FORMAT.replace(b'"}\n', f'","attempts":{github_outbox.MAX_ATTEMPTS - 1}}}\n'.encode())
    outbox.put(_OLD_ID, almost)
    github_outbox.enqueue([_entry("later")])

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(_Deliverer({_path("old"): Delivery.UNAVAILABLE})).handled == 2

    assert outbox.entries() == []
    assert f"Dropped {_path('old')} from the credential log" in caplog.text


def test_counting_an_attempt_leaves_an_entry_removed_meanwhile_removed(bucket_outbox):
    github_outbox.enqueue([_entry("stuck"), _entry("later")])
    stuck = bucket_outbox.names()[0]
    deliverer = _Deliverer({_path("stuck"): Delivery.UNAVAILABLE})

    def _a_late_run_removes_the_stuck_one(entry):
        if entry.path == _path("later"):
            bucket_outbox.delete(stuck)
        return deliverer(entry)

    assert github_outbox.flush(_a_late_run_removes_the_stuck_one).handled == 1

    assert bucket_outbox.entries() == []


def test_a_delivery_that_raises_keeps_the_entry_and_backs_off(outbox, caplog):
    github_outbox.enqueue([_entry("one")])

    def _raises(_entry):
        raise RuntimeError("the deliverer broke")

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        run = github_outbox.flush(_raises)

    assert run.handled == 0 and run.not_before > 0
    assert len(outbox.entries()) == 1
    assert "Could not deliver logs/unknown/one.json to the credential log; it stays queued" in caplog.text


def test_an_entry_that_does_not_decode_is_removed_with_a_warning(outbox, caplog):
    github_outbox.enqueue([_entry("one")])
    outbox.put("00000000T000000000000Z-0bad0bad", b"not an entry")
    deliverer = _Deliverer()

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(deliverer).handled == 1

    assert deliverer.paths == ["logs/unknown/one.json"]
    assert outbox.names() == []
    assert "00000000T000000000000Z-0bad0bad" in caplog.text
    assert "from the credential log outbox: it is not an entry this server reads" in caplog.text
    assert "not an entry" not in caplog.text.replace("is not an entry this server reads", "")


def test_an_entry_removed_meanwhile_is_skipped(outbox):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    second = outbox.names()[1]
    deliverer = _Deliverer()

    def _removes_the_second(entry):
        outbox.delete(second)
        return deliverer(entry)

    assert github_outbox.flush(_removes_the_second).handled == 1
    assert deliverer.paths == ["logs/unknown/one.json"]


def test_a_run_that_stalled_past_its_lease_starts_no_new_delivery(outbox, clock):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    deliverer = _Deliverer()

    def _stalls(entry):
        clock.now += github_outbox.LEASE_SECONDS - github_outbox.LEASE_MARGIN_SECONDS + 1
        return deliverer(entry)

    assert github_outbox.flush(_stalls).handled == 1
    assert [entry.path for entry in outbox.entries()] == ["logs/unknown/two.json"]


def test_a_flush_started_while_another_holds_the_lease_does_nothing(outbox):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    inner = _Deliverer()
    inner_runs = []

    def _flushes_again(entry):
        inner_runs.append(github_outbox.flush(inner))
        return Delivery.DELIVERED

    assert github_outbox.flush(_flushes_again).handled == 2
    assert inner_runs == [github_outbox.FlushRun(0, 0.0)] * 2
    assert inner.paths == []


def test_two_flushers_at_once_deliver_each_entry_once(outbox):
    github_outbox.enqueue([_entry(f"e{index}") for index in range(10)])
    deliverer = _Deliverer()
    barrier = threading.Barrier(2)
    runs = []

    def _flusher():
        barrier.wait()
        runs.append(github_outbox.flush(deliverer))

    threads = [threading.Thread(target=_flusher) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(deliverer.paths) == sorted(f"logs/unknown/e{index}.json" for index in range(10))
    assert sorted(run.handled for run in runs) in ([0, 10], [10, 10]) and sum(run.handled for run in runs) == 10
    assert outbox.entries() == []


def test_a_lease_held_by_a_process_blocks_the_outbox_until_the_process_stops(local_outbox):
    github_outbox.enqueue([_entry("one")])
    deliverer = _Deliverer()
    held = open(local_outbox.root / ".lease", "a+b")
    fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(0, 0.0)
    assert deliverer.paths == []

    held.close()  # A stopped process's locks go with it.

    assert github_outbox.flush(deliverer).handled == 1
    assert deliverer.paths == ["logs/unknown/one.json"]


@pytest.mark.parametrize("lease", [b"", b"not json", b"[1]", b'{"notBefore": "soon", "until": null}'])
def test_a_lease_file_that_does_not_read_is_no_lease(local_outbox, lease):
    github_outbox.enqueue([_entry("one")])
    (local_outbox.root / ".lease").write_bytes(lease)

    assert github_outbox.flush(_Deliverer()).handled == 1
    assert json.loads((local_outbox.root / ".lease").read_bytes()) == {"until": 0.0, "notBefore": 0.0}


def test_a_run_that_fails_still_gives_the_lease_back(outbox, monkeypatch):
    github_outbox.enqueue([_entry("one")])
    remove = outbox.backend.remove
    failures = [OSError("read-only")]

    def _fails_once(self, name):
        if failures:
            raise failures.pop()
        remove(self, name)

    monkeypatch.setattr(outbox.backend, "remove", _fails_once)
    with pytest.raises(OSError, match="read-only"):
        github_outbox.flush(_Deliverer())

    assert github_outbox.flush(_Deliverer()).handled == 1


def test_past_its_count_the_outbox_drops_an_entry_with_a_warning(outbox, monkeypatch, caplog):
    monkeypatch.setattr(github_outbox, "MAX_ENTRIES", 2)
    github_outbox.enqueue([_entry("one")])

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_entry("two"), _entry("three", b"secret content")]) == 1

    assert [entry.path for entry in outbox.entries()] == ["logs/unknown/one.json", "logs/unknown/two.json"]
    assert "The credential log outbox is full (2 entries" in caplog.text
    assert "dropped logs/unknown/three.json" in caplog.text
    assert "secret content" not in caplog.text


def test_past_its_bytes_the_outbox_drops_an_entry_with_a_warning(outbox, monkeypatch, caplog):
    small = len(github_outbox.encode_entry(_entry("one")))
    monkeypatch.setattr(github_outbox, "MAX_BYTES", 2 * small)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_entry("one"), _entry("big", b"x" * 100), _entry("two")]) == 2

    assert [entry.path for entry in outbox.entries()] == ["logs/unknown/one.json", "logs/unknown/two.json"]
    assert "dropped logs/unknown/big.json" in caplog.text


def test_an_outbox_that_cannot_be_listed_still_takes_its_entries(outbox, monkeypatch, caplog):
    def _cannot_list(self):
        raise OSError("listing failed")

    monkeypatch.setattr(outbox.backend, "held", _cannot_list)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_entry("one"), _entry("two")]) == 2

    assert len(outbox.entries()) == 2
    assert "queuing 2 entries without its bound: listing failed" in caplog.text


def test_an_entry_that_cannot_be_written_is_dropped_and_the_rest_are_queued(outbox, monkeypatch, caplog):
    write = outbox.backend.write
    attempts = []

    def _first_fails(self, entry_id, data):
        attempts.append(entry_id)
        if len(attempts) == 1:
            raise OSError("disk full")
        write(self, entry_id, data)

    monkeypatch.setattr(outbox.backend, "write", _first_fails)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_entry("one"), _entry("two")]) == 1

    assert [entry.path for entry in outbox.entries()] == ["logs/unknown/two.json"]
    assert "Could not queue logs/unknown/one.json for the credential log: disk full" in caplog.text


def test_the_outbox_folder_is_its_setting_else_under_the_instance(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", "/elsewhere/outbox")
    assert github_outbox.outbox_dir() == "/elsewhere/outbox"

    monkeypatch.delenv("FIDO_SERVER_GITHUB_OUTBOX_DIR")
    assert github_outbox.outbox_dir().endswith(os.path.join("instance", "github-outbox"))


def test_the_bucket_outbox_is_outside_the_visitors_data(bucket_outbox):
    github_outbox.enqueue([_entry("one")])
    github_outbox.flush(_Deliverer({"logs/unknown/one.json": Delivery.UNAVAILABLE}))

    names = sorted(bucket_outbox.bucket.objects)
    assert len(names) == 2 and names[1] == "github-outbox/lease"
    assert names[0].startswith("github-outbox/entries/")
    assert bucket_outbox.bucket.content_types == {names[0]: "application/octet-stream", names[1]: "application/json"}


def _lease(bucket) -> dict:
    return json.loads(bucket.objects["github-outbox/lease"][0])


def test_a_live_lease_of_another_instance_is_left_and_one_past_its_time_is_taken_over(bucket_outbox, clock):
    github_outbox.enqueue([_entry("one")])
    bucket_outbox.bucket.put("github-outbox/lease", json.dumps({"until": clock.now + 10, "notBefore": 0}).encode())
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(0, 0.0)
    assert deliverer.paths == []

    clock.now += 11  # The instance holding it stopped: its lease lapses.

    assert github_outbox.flush(deliverer).handled == 1
    assert deliverer.paths == ["logs/unknown/one.json"]
    assert _lease(bucket_outbox.bucket) == {"until": 0.0, "notBefore": 0.0}


def test_a_lease_object_that_does_not_read_is_taken_over(bucket_outbox):
    github_outbox.enqueue([_entry("one")])
    bucket_outbox.bucket.put("github-outbox/lease", b"not json")

    assert github_outbox.flush(_Deliverer()).handled == 1


def test_of_two_instances_taking_a_lease_at_once_one_wins(bucket_outbox, monkeypatch):
    github_outbox.enqueue([_entry("one")])
    bucket = bucket_outbox.bucket
    bucket.put("github-outbox/lease", json.dumps({"until": 0, "notBefore": 0}).encode())

    def _the_other_instance_writes_first(name):
        if name == "github-outbox/lease" and bucket.on_download:
            bucket.on_download.clear()
            bucket.put(name, json.dumps({"until": 1e12, "notBefore": 0}).encode())

    bucket.on_download.append(_the_other_instance_writes_first)
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(0, 0.0)
    assert deliverer.paths == []


def test_a_run_that_outlasted_its_lease_leaves_the_flusher_that_took_over_in_charge(bucket_outbox, clock, caplog):
    github_outbox.enqueue([_entry("one"), _entry("two"), _entry("three")])
    bucket = bucket_outbox.bucket
    late = _Deliverer()
    took_over = _Deliverer({"logs/unknown/three.json": Delivery.UNAVAILABLE})
    runs = []

    def _stalls_past_its_lease(entry):
        clock.now += github_outbox.LEASE_SECONDS + 1
        runs.append(github_outbox.flush(took_over))
        return late(entry)

    with caplog.at_level(logging.INFO, logger=github_outbox.__name__):
        assert github_outbox.flush(_stalls_past_its_lease).handled == 1

    # The flusher that took over delivered what it found, "one" too: a delivery made twice
    # finds its file at its path (github_mirror). The late run started nothing more.
    assert took_over.paths == ["logs/unknown/one.json", "logs/unknown/two.json", "logs/unknown/three.json"]
    assert late.paths == ["logs/unknown/one.json"]
    assert runs == [github_outbox.FlushRun(2, clock.now + github_outbox.BACKOFF_SECONDS)]
    assert _lease(bucket) == {"until": 0.0, "notBefore": clock.now + github_outbox.BACKOFF_SECONDS}
    assert "took the credential log outbox's lease over from a run that outlasted it" in caplog.text
    assert [entry.path for entry in bucket_outbox.entries()] == ["logs/unknown/three.json"]


def test_a_lease_that_cannot_be_given_back_lapses_by_itself(bucket_outbox, monkeypatch, caplog):
    github_outbox.enqueue([_entry("one")])
    upload = github_outbox.cloud.upload_bytes_at_generation
    writes = []

    def _second_write_fails(*args, **kwargs):
        writes.append(args)
        if len(writes) == 2:
            raise OSError("bucket unavailable")
        return upload(*args, **kwargs)

    monkeypatch.setattr(github_outbox.cloud, "upload_bytes_at_generation", _second_write_fails)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(_Deliverer()).handled == 1

    assert "Could not give the credential log outbox's lease back; it lapses by itself: bucket unavailable" in caplog.text
    assert _lease(bucket_outbox.bucket)["until"] > 0


def test_a_process_flushes_at_most_once_an_interval_unless_kicked(outbox, clock):
    deliverer = _Deliverer()
    github_outbox.enqueue([_entry("one")])
    github_outbox.schedule_flush(deliverer)
    github_outbox.enqueue([_entry("two")])

    clock.now += github_outbox.FLUSH_INTERVAL_SECONDS - 1
    github_outbox.schedule_flush(deliverer)
    assert deliverer.paths == ["logs/unknown/one.json"]

    github_outbox.schedule_flush(deliverer, kick=True)
    assert deliverer.paths == ["logs/unknown/one.json", "logs/unknown/two.json"]

    github_outbox.enqueue([_entry("three")])
    clock.now += github_outbox.FLUSH_INTERVAL_SECONDS
    github_outbox.schedule_flush(deliverer)
    assert deliverer.paths[-1] == "logs/unknown/three.json"


def test_a_process_leaves_the_outbox_alone_while_it_backs_off_even_when_kicked(outbox, clock):
    github_outbox.enqueue([_entry("one")])
    refusing = _Deliverer({"logs/unknown/one.json": Delivery.UNAVAILABLE})
    github_outbox.schedule_flush(refusing)
    assert github_outbox.FLUSH.not_before == clock.now + github_outbox.BACKOFF_SECONDS

    clock.now += github_outbox.BACKOFF_SECONDS - 1
    github_outbox.schedule_flush(refusing, kick=True)
    assert refusing.paths == ["logs/unknown/one.json"]

    clock.now += 1
    deliverer = _Deliverer()
    github_outbox.schedule_flush(deliverer, kick=True)
    assert deliverer.paths == ["logs/unknown/one.json"]
    assert outbox.entries() == []


def test_a_new_process_delivers_what_an_earlier_one_queued(outbox, monkeypatch):
    github_outbox.enqueue([_entry("one")])
    monkeypatch.setattr(github_outbox, "FLUSH", github_outbox.FlushState())  # The instance stopped.
    deliverer = _Deliverer()

    github_outbox.schedule_flush(deliverer)

    assert deliverer.paths == ["logs/unknown/one.json"]


def test_a_run_that_fails_is_logged_and_the_process_tries_again_later(outbox, monkeypatch, clock, caplog):
    github_outbox.enqueue([_entry("one")])
    names = outbox.backend.names
    failures = [OSError("listing failed")]

    def _fails_once(self):
        if failures:
            raise failures.pop()
        return names(self)

    monkeypatch.setattr(outbox.backend, "names", _fails_once)
    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        github_outbox.schedule_flush(_Deliverer())
    assert "Could not flush the credential log outbox" in caplog.text

    clock.now += github_outbox.FLUSH_INTERVAL_SECONDS
    deliverer = _Deliverer()
    github_outbox.schedule_flush(deliverer)
    assert deliverer.paths == ["logs/unknown/one.json"]


def test_a_run_goes_on_a_worker_and_a_kick_meanwhile_runs_it_again(outbox, monkeypatch):
    monkeypatch.setattr(github_outbox, "FLUSH_ASYNC", True)
    started, release = threading.Event(), threading.Event()
    deliverer = _Deliverer()

    def _slow(entry):
        if entry.path.endswith("/one.json"):
            started.set()
            assert release.wait(10)
        return deliverer(entry)

    github_outbox.enqueue([_entry("one")])
    github_outbox.schedule_flush(_slow)
    worker = github_outbox.FLUSH.worker
    assert worker is not None and worker.name == "credential-log-flush" and worker.daemon
    assert started.wait(10)

    github_outbox.enqueue([_entry("two")])
    github_outbox.schedule_flush(_slow)  # Not a kick: no second run for it.
    assert github_outbox.FLUSH.pending is False
    github_outbox.schedule_flush(_slow, kick=True)
    assert github_outbox.FLUSH.pending is True
    release.set()
    worker.join(10)

    assert deliverer.paths == ["logs/unknown/one.json", "logs/unknown/two.json"]
    assert github_outbox.FLUSH.worker is None and github_outbox.FLUSH.pending is False


def test_a_kick_while_a_worker_runs_waits_out_a_backoff_its_run_found(outbox, monkeypatch):
    monkeypatch.setattr(github_outbox, "FLUSH_ASYNC", True)
    started, release = threading.Event(), threading.Event()
    calls = []

    def _refuses(entry):
        calls.append(entry.path)
        started.set()
        assert release.wait(10)
        return Delivery.UNAVAILABLE

    github_outbox.enqueue([_entry("one")])
    github_outbox.schedule_flush(_refuses)
    worker = github_outbox.FLUSH.worker
    assert started.wait(10)
    github_outbox.schedule_flush(_refuses, kick=True)
    release.set()
    worker.join(10)

    assert calls == ["logs/unknown/one.json"]
    assert github_outbox.FLUSH.worker is None and github_outbox.FLUSH.pending is False
