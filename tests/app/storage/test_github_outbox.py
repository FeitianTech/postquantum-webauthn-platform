"""Tests for github_outbox: the credential log's queue, its bound, its lease and its flush."""
from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
import types
from collections.abc import Callable
from typing import NamedTuple

import pytest

from server.app.storage import common as storage_common
from server.app.storage import github_outbox
from server.app.storage.github_outbox import Delivery, OutboxEntry
from tests.app.log_lines import FORGED, one_line_naming
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

    def budget(self, name: str = "metadata-budget") -> bytes | None:
        path = self.root / f".{name}"
        return path.read_bytes() if path.exists() else None

    def put_budget(self, data: bytes, name: str = "metadata-budget") -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / f".{name}").write_bytes(data)

    def break_budget(self, name: str) -> None:
        """Make the budget unreadable: a folder where its file goes."""

        (self.root / f".{name}").mkdir(parents=True)


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

    def budget(self, name: str = "metadata-budget") -> bytes | None:
        return self.bucket.objects.get(f"github-outbox/{name}", (None, 0))[0]

    def put_budget(self, data: bytes, name: str = "metadata-budget") -> None:
        self.bucket.put(f"github-outbox/{name}", data)

    def break_budget(self, name: str) -> None:
        self.bucket.failing[f"github-outbox/{name}"] = fake_gcs.ServiceUnavailable("the bucket is unavailable")


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


def test_an_entry_found_at_its_path_already_is_removed_but_counts_no_attempt_on_entries_before_it(outbox, clock):
    github_outbox.enqueue([_entry("one"), _entry("two")])
    deliverer = _Deliverer({_path("one"): Delivery.UNAVAILABLE, _path("two"): Delivery.FOUND})

    # Found by reads alone, it is no sign that GitHub takes writes: the outbox backs off.
    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(1, clock.now + github_outbox.BACKOFF_SECONDS)

    assert _attempts(outbox) == {_path("one"): 0}


def test_entries_passed_over_before_one_found_are_counted_when_a_later_one_is_delivered(outbox, clock):
    github_outbox.enqueue([_entry("one"), _entry("two"), _entry("three")])
    deliverer = _Deliverer({_path("one"): Delivery.UNAVAILABLE, _path("two"): Delivery.FOUND})

    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(2, 0.0)

    assert _attempts(outbox) == {_path("one"): 1}


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


# A visitor's metadata file, at a path made from the name it was uploaded with.
_FORGED_ENTRY = OutboxEntry("metadata", f"metadata/{FORGED}", "metadata: add it", b"{}")


def test_an_entry_dropped_from_a_full_outbox_is_named_on_one_line(outbox, monkeypatch, caplog):
    monkeypatch.setattr(github_outbox, "MAX_ENTRIES", 0)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_FORGED_ENTRY]) == 0

    one_line_naming(caplog, github_outbox.__name__, _FORGED_ENTRY.path)


def test_an_entry_that_cannot_be_written_is_named_on_one_line(outbox, monkeypatch, caplog):
    def _fails(self, entry_id, data):
        raise OSError("disk full")

    monkeypatch.setattr(outbox.backend, "write", _fails)

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.enqueue([_FORGED_ENTRY]) == 0

    one_line_naming(caplog, github_outbox.__name__, _FORGED_ENTRY.path)


def test_an_entry_whose_delivery_raises_is_named_on_one_line(outbox, caplog):
    github_outbox.enqueue([_FORGED_ENTRY])

    def _raises(_entry):
        raise RuntimeError("the deliverer broke")

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        github_outbox.flush(_raises)

    one_line_naming(caplog, github_outbox.__name__, _FORGED_ENTRY.path)


def test_an_entry_given_up_is_named_on_one_line(outbox, caplog):
    github_outbox.enqueue([_FORGED_ENTRY._replace(attempts=github_outbox.MAX_ATTEMPTS - 1), _entry("later")])

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        github_outbox.flush(_Deliverer({_FORGED_ENTRY.path: Delivery.UNAVAILABLE}))

    assert outbox.entries() == []
    one_line_naming(caplog, github_outbox.__name__, _FORGED_ENTRY.path)


# The bucket's budget object, and the day the clock fixture's time falls on (UTC).
_BUDGET = "github-outbox/metadata-budget"
_DAY = "1970-01-12"


def _budget_of(files: int, size: int, day: str = _DAY) -> bytes:
    return json.dumps({"day": day, "files": files, "bytes": size}).encode()


@pytest.fixture
def small_budget(monkeypatch):
    """A day's metadata budget of 3 files and 100 bytes."""

    monkeypatch.setattr(github_outbox, "METADATA_FILES_A_DAY", 3)
    monkeypatch.setattr(github_outbox, "METADATA_BYTES_A_DAY", 100)


class _Budget(NamedTuple):
    """A day's budget: its object's name, and how a test takes it."""

    name: str
    take: Callable[[list[int]], list[bool]]


def _take_registration_budget(sizes: list[int]) -> list[bool]:
    return github_outbox._take_budget(
        "registration-budget", github_outbox.REGISTRATIONS_A_DAY, github_outbox.REGISTRATION_BYTES_A_DAY, sizes
    )


@pytest.fixture(params=["metadata", "registration"])
def small_budgets(request, monkeypatch):
    """Each day's budget of 3 files and 100 bytes in turn: the metadata's and the registrations'."""

    monkeypatch.setattr(github_outbox, "METADATA_FILES_A_DAY", 3)
    monkeypatch.setattr(github_outbox, "METADATA_BYTES_A_DAY", 100)
    monkeypatch.setattr(github_outbox, "REGISTRATIONS_A_DAY", 3)
    monkeypatch.setattr(github_outbox, "REGISTRATION_BYTES_A_DAY", 100)
    if request.param == "metadata":
        return _Budget("metadata-budget", github_outbox.take_metadata_budget)
    return _Budget("registration-budget", _take_registration_budget)


def test_the_metadata_budget_takes_files_until_the_day_s_files_or_bytes_run_out(outbox, clock, small_budget):
    assert github_outbox.take_metadata_budget([40, 40, 30, 10]) == [True, True, False, True]
    assert github_outbox.take_metadata_budget([1]) == [False]

    assert json.loads(outbox.budget()) == {"day": _DAY, "files": 3, "bytes": 90}
    assert outbox.names() == []


def test_the_metadata_budget_starts_again_the_next_day(outbox, clock, small_budget):
    assert github_outbox.take_metadata_budget([100, 1]) == [True, False]

    clock.now += 24 * 60 * 60

    assert github_outbox.take_metadata_budget([1]) == [True]
    assert json.loads(outbox.budget()) == {"day": "1970-01-13", "files": 1, "bytes": 1}


@pytest.mark.parametrize(
    "stored",
    [
        b"not json",
        b"\xff",
        b"[1]",
        _budget_of(3, 90, day="1970-01-11"),
        b'{"day": "1970-01-12", "files": true, "bytes": 0}',
        b'{"day": "1970-01-12", "files": "3", "bytes": 0}',
        b'{"day": "1970-01-12", "files": -1, "bytes": 0}',
        b'{"day": "1970-01-12", "files": 3}',
    ],
)
def test_a_metadata_budget_that_does_not_read_or_names_another_day_is_empty(outbox, clock, small_budget, stored):
    outbox.put_budget(stored)

    assert github_outbox.take_metadata_budget([5]) == [True]
    assert json.loads(outbox.budget()) == {"day": _DAY, "files": 1, "bytes": 5}


def test_two_requests_at_once_take_the_last_of_a_budget_once(outbox, clock, small_budgets):
    outbox.put_budget(_budget_of(2, 0), small_budgets.name)
    start = threading.Barrier(2)
    results = []

    def _take() -> None:
        start.wait()
        results.append(small_budgets.take([1]))

    workers = [threading.Thread(target=_take) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert sorted(results) == [[False], [True]]
    assert json.loads(outbox.budget(small_budgets.name)) == {"day": _DAY, "files": 3, "bytes": 1}


def test_a_spent_metadata_budget_is_not_written_again(bucket_outbox, clock, small_budget):
    github_outbox.take_metadata_budget([100])
    writes = list(bucket_outbox.bucket.writes)

    assert github_outbox.take_metadata_budget([1, 1]) == [False, False]

    assert bucket_outbox.bucket.writes == writes == [_BUDGET]


def test_a_budget_another_instance_wrote_first_is_read_again(bucket_outbox, clock, small_budgets):
    bucket = bucket_outbox.bucket
    stored = f"github-outbox/{small_budgets.name}"
    bucket.put(stored, _budget_of(1, 10))

    def _another_instance_takes_one(name: str) -> None:
        if name == stored:
            bucket.on_download.remove(_another_instance_takes_one)
            bucket.put(stored, _budget_of(2, 20))

    bucket.on_download.append(_another_instance_takes_one)

    assert small_budgets.take([5, 5]) == [True, False]
    assert json.loads(bucket_outbox.budget(small_budgets.name)) == {"day": _DAY, "files": 3, "bytes": 25}


def test_a_budget_others_always_write_first_raises_after_its_tries(bucket_outbox, clock, small_budgets):
    bucket = bucket_outbox.bucket
    stored = f"github-outbox/{small_budgets.name}"
    bucket.put(stored, _budget_of(0, 0))
    bucket.on_download.append(lambda name: bucket.put(stored, _budget_of(0, 0)))

    with pytest.raises(RuntimeError, match="wrote it first 5 times in a row"):
        small_budgets.take([1])

    assert [name for name, _options in bucket.download_options] == [stored] * github_outbox.BUDGET_TRIES
    assert stored not in bucket.writes


def test_a_budget_that_cannot_be_read_raises(bucket_outbox, clock, small_budgets):
    bucket_outbox.break_budget(small_budgets.name)

    with pytest.raises(fake_gcs.ServiceUnavailable):
        small_budgets.take([1])


def test_the_metadata_budget_is_one_object_beside_the_outbox_s_entries(bucket_outbox, clock):
    github_outbox.take_metadata_budget([1])

    assert bucket_outbox.bucket.content_types == {_BUDGET: "application/json"}
    assert bucket_outbox.names() == []


def test_the_local_metadata_budget_is_a_file_of_the_outbox_folder_ignored_by_git(local_outbox, clock):
    github_outbox.take_metadata_budget([1])

    assert sorted(os.listdir(local_outbox.root)) == [".gitignore", ".metadata-budget", ".metadata-budget.lock"]
    assert "*" in (local_outbox.root / ".gitignore").read_text().splitlines()


# The registrations' budget, which the flusher applies: checked before a delivery, counted after one.
_REGISTRATION_BUDGET = "registration-budget"
_METADATA_ENTRY = OutboxEntry("metadata", "metadata/a.json", "metadata: add a.json", b"{}")


@pytest.fixture
def small_registration_budget(monkeypatch):
    """A day's registration budget of 3 entries and 100 bytes."""

    monkeypatch.setattr(github_outbox, "REGISTRATIONS_A_DAY", 3)
    monkeypatch.setattr(github_outbox, "REGISTRATION_BYTES_A_DAY", 100)


def _counted(outbox) -> dict:
    return json.loads(outbox.budget(_REGISTRATION_BUDGET))


def _warnings(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.name == github_outbox.__name__]


def test_an_outage_spends_nothing_of_the_registration_budget(outbox, clock, small_registration_budget):
    names = ["one", "two", "three"]
    github_outbox.enqueue([_entry(name) for name in names])
    down = _Deliverer({_path(name): Delivery.UNAVAILABLE for name in names})

    for _ in range(3):
        assert github_outbox.flush(down).handled == 0
        clock.now += github_outbox.BACKOFF_SECONDS

    assert outbox.budget(_REGISTRATION_BUDGET) is None
    assert _attempts(outbox) == {_path(name): 0 for name in names}

    up = _Deliverer()
    assert github_outbox.flush(up).handled == 3

    assert up.paths == [_path(name) for name in names]
    assert outbox.names() == []
    assert _counted(outbox) == {"day": _DAY, "files": 3, "bytes": 6}


def test_a_registration_past_the_day_s_count_is_dropped_before_github_is_asked(outbox, clock, monkeypatch, caplog):
    monkeypatch.setattr(github_outbox, "REGISTRATIONS_A_DAY", 1)
    github_outbox.enqueue([_entry("one"), _entry("two")])
    deliverer = _Deliverer()

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(deliverer).handled == 2

    assert deliverer.paths == [_path("one")]
    assert outbox.names() == []
    assert _counted(outbox) == {"day": _DAY, "files": 1, "bytes": 2}
    assert _warnings(caplog) == [
        "Dropped logs/unknown/two.json from the credential log: today's budget of 1 registrations and 64 MiB has no"
        " room for it; it starts again at 00:00 UTC"
    ]


def test_a_registration_past_the_day_s_bytes_is_dropped_before_github_is_asked(outbox, clock, small_registration_budget):
    github_outbox.enqueue([_entry("big", b"x" * 60), _entry("bigger", b"x" * 50), _entry("small", b"x" * 40)])
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer).handled == 3

    assert deliverer.paths == [_path("big"), _path("small")]
    assert outbox.names() == []
    assert _counted(outbox) == {"day": _DAY, "files": 2, "bytes": 100}


def test_metadata_entries_are_delivered_while_the_registration_budget_is_spent(outbox, clock, small_registration_budget):
    outbox.put_budget(_budget_of(3, 6), _REGISTRATION_BUDGET)
    github_outbox.enqueue([_entry("one"), _METADATA_ENTRY, _entry("two")])
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer).handled == 3

    assert deliverer.paths == [_METADATA_ENTRY.path]
    assert _counted(outbox) == {"day": _DAY, "files": 3, "bytes": 6}
    assert outbox.budget() is None


def test_the_registration_budget_starts_again_the_next_day(outbox, clock, small_registration_budget):
    outbox.put_budget(_budget_of(3, 6), _REGISTRATION_BUDGET)
    github_outbox.enqueue([_entry("one")])
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer).handled == 1
    assert deliverer.paths == []

    clock.now += 24 * 60 * 60
    github_outbox.enqueue([_entry("two")])

    assert github_outbox.flush(deliverer).handled == 1
    assert deliverer.paths == [_path("two")]
    assert _counted(outbox) == {"day": "1970-01-13", "files": 1, "bytes": 2}


def test_registrations_stay_queued_and_every_flusher_backs_off_while_their_budget_cannot_be_read(outbox, clock):
    outbox.break_budget(_REGISTRATION_BUDGET)
    github_outbox.enqueue([_entry("one"), _entry("two")])
    deliverer = _Deliverer()

    run = github_outbox.flush(deliverer)

    assert run == github_outbox.FlushRun(0, clock.now + github_outbox.BACKOFF_SECONDS)
    assert deliverer.paths == []
    assert _attempts(outbox) == {_path("one"): 0, _path("two"): 0}


def test_registrations_whose_budget_cannot_be_read_get_no_failed_attempt_when_metadata_after_them_is_delivered(
    outbox, clock, caplog
):
    outbox.break_budget(_REGISTRATION_BUDGET)
    github_outbox.enqueue([_entry("one"), _METADATA_ENTRY])
    deliverer = _Deliverer()

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(deliverer).handled == 1

    assert deliverer.paths == [_METADATA_ENTRY.path]
    assert _attempts(outbox) == {_path("one"): 0}
    assert _warnings(caplog) == ["Could not read today's registration budget; logs/unknown/one.json stays queued"]


def test_a_run_stops_after_a_few_registrations_in_a_row_whose_budget_cannot_be_read(outbox, clock):
    outbox.break_budget(_REGISTRATION_BUDGET)
    names = [f"r{index}" for index in range(github_outbox.MAX_UNAVAILABLE_IN_A_ROW)]
    github_outbox.enqueue([*(_entry(name) for name in names), _METADATA_ENTRY])
    deliverer = _Deliverer()

    assert github_outbox.flush(deliverer) == github_outbox.FlushRun(0, clock.now + github_outbox.BACKOFF_SECONDS)

    assert deliverer.paths == []
    assert _attempts(outbox) == {**{_path(name): 0 for name in names}, _METADATA_ENTRY.path: 0}


@pytest.mark.parametrize("delivery", [Delivery.FOUND, Delivery.DROPPED])
def test_a_registration_found_already_or_refused_is_not_counted_in_the_budget(outbox, clock, delivery):
    github_outbox.enqueue([_entry("one")])

    assert github_outbox.flush(_Deliverer({_path("one"): delivery})).handled == 1

    assert outbox.names() == []
    assert outbox.budget(_REGISTRATION_BUDGET) is None


def test_a_delivered_registration_that_cannot_be_counted_is_removed_with_a_warning(outbox, clock, monkeypatch, caplog):
    def _cannot_write(self, name, change):
        raise OSError("the budget cannot be written")

    monkeypatch.setattr(outbox.backend, "update_budget", _cannot_write)
    github_outbox.enqueue([_entry("one")])
    deliverer = _Deliverer()

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(deliverer).handled == 1

    assert deliverer.paths == [_path("one")]
    assert outbox.names() == []
    assert _warnings(caplog) == [
        "Delivered logs/unknown/one.json to the credential log but could not count it in today's registration budget:"
        " the budget cannot be written"
    ]


def test_a_registration_dropped_past_its_budget_counts_no_attempt_on_entries_before_it(outbox, clock, small_registration_budget):
    outbox.put_budget(_budget_of(3, 6), _REGISTRATION_BUDGET)
    github_outbox.enqueue([_METADATA_ENTRY, _entry("one")])
    deliverer = _Deliverer({_METADATA_ENTRY.path: Delivery.UNAVAILABLE})

    assert github_outbox.flush(deliverer).handled == 1

    assert deliverer.paths == [_METADATA_ENTRY.path]
    assert outbox.entries() == [_METADATA_ENTRY]


def test_the_registration_budget_is_one_object_beside_the_outbox_s_entries(bucket_outbox, clock):
    github_outbox.enqueue([_entry("one")])
    github_outbox.flush(_Deliverer())

    assert bucket_outbox.bucket.content_types["github-outbox/registration-budget"] == "application/json"
    assert sorted(bucket_outbox.bucket.objects) == ["github-outbox/lease", "github-outbox/registration-budget"]


def test_the_local_registration_budget_is_a_file_of_the_outbox_folder_written_once_one_is_delivered(local_outbox, clock):
    github_outbox.enqueue([_entry("one")])
    github_outbox.flush(_Deliverer({_path("one"): Delivery.UNAVAILABLE}))

    assert ".registration-budget" not in os.listdir(local_outbox.root)

    clock.now += github_outbox.BACKOFF_SECONDS
    github_outbox.flush(_Deliverer())

    assert sorted(os.listdir(local_outbox.root)) == [
        ".gitignore", ".lease", ".registration-budget", ".registration-budget.lock"
    ]


def test_an_entry_dropped_past_the_registration_budget_is_named_on_one_line(outbox, clock, monkeypatch, caplog):
    monkeypatch.setattr(github_outbox, "REGISTRATIONS_A_DAY", 0)
    github_outbox.enqueue([_FORGED_ENTRY._replace(kind="registration")])

    with caplog.at_level(logging.WARNING, logger=github_outbox.__name__):
        assert github_outbox.flush(_Deliverer()).handled == 1

    one_line_naming(caplog, github_outbox.__name__, _FORGED_ENTRY.path)


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
        # The lease's writes only: the delivered registration's count is written between them.
        if args[0] == "github-outbox/lease":
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
