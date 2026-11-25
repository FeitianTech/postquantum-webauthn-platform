"""The credential log's outbox: the files waiting to be copied to the log repository on GitHub.

A registration's log entry and an uploaded metadata file are queued here once their save
succeeded (``enqueue``), each with the path it lands at in the repository, fixed then, and
delivered later by ``flush``. One flusher at a time holds the outbox's lease: GitHub takes new
files one at a time (its create-file endpoint refuses calls made in parallel), and when it cannot
take one a run goes on to the next few: an entry it never takes, though it takes later ones, is
given up after a few such runs, while an outage gives up nothing and every flusher backs off
together. A delivery made twice finds its file at its path, so an entry is delivered at least
once and never becomes two files.

On Cloud Storage the outbox is ``github-outbox/``, outside the visitors' ``user-data/``, which
the idle sweep removes: each entry ``github-outbox/entries/<id>``, and the lease
``github-outbox/lease``, written only at the generation it was read at, as the stores write.
Locally it is a folder (``FIDO_SERVER_GITHUB_OUTBOX_DIR``, else ``instance/github-outbox``): each
entry ``<id>.entry``, and the lease an ``flock`` on ``.lease``. Either lease also keeps when the
outbox may next be tried. Beside them, the day's budgets, written by compare-and-swap: of uploaded
metadata queued (``take_metadata_budget``), ``github-outbox/metadata-budget`` or ``.metadata-budget``,
and of registrations delivered (``_delivered``), ``github-outbox/registration-budget`` or
``.registration-budget``. docs/STORAGE.md has the rules.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import NamedTuple

from .. import log_text
from ..config.paths import GITHUB_OUTBOX_STORE, store_dir
from . import cloud, common

logger = logging.getLogger(__name__)

__all__ = [
    "Delivery",
    "FlushRun",
    "FlushState",
    "Lease",
    "OutboxEntry",
    "decode_entry",
    "encode_entry",
    "enqueue",
    "flush",
    "outbox_dir",
    "schedule_flush",
    "take_metadata_budget",
]

# The outbox's bound: an entry past either is dropped with a warning.
MAX_ENTRIES = 1_000
MAX_BYTES = 256 * 1024 * 1024
# The uploaded metadata queued in a day (UTC), for all visitors together: a request without a
# cookie gets a namespace of its own, so the upload quotas bound nothing the log keeps.
METADATA_FILES_A_DAY = 50
METADATA_BYTES_A_DAY = 8 * 1024 * 1024
# The registrations delivered in a day (UTC), for all visitors together, counted only when
# delivered: an outage spends nothing, and one past it is dropped before GitHub is asked.
REGISTRATIONS_A_DAY = 1_000
REGISTRATION_BYTES_A_DAY = 64 * 1024 * 1024
# How many times a request reads the budget again when another request wrote it first.
BUDGET_TRIES = 5
# How long a run holds the lease, and how much of it must be left to start a delivery: a run
# that stalled past its lease (a throttled CPU) starts nothing another flusher may be doing.
LEASE_SECONDS = 300.0
LEASE_MARGIN_SECONDS = 60.0
# How long every flusher leaves the outbox after GitHub could not take a delivery.
BACKOFF_SECONDS = 300.0
# How many entries in a row a run tries that GitHub cannot take before it stops: an outage, a
# rate limit or a bad token costs that many calls, and an entry GitHub never takes does not
# hold back the ones behind it.
MAX_UNAVAILABLE_IN_A_ROW = 3
# An entry GitHub could not take is counted a failed attempt only when it took a later entry in
# the same run (it was working: the entry is the problem), and given up at this count. Failures
# with no delivery after them count nothing, or an outage would empty the outbox.
MAX_ATTEMPTS = 5
# The most entries one run delivers.
RUN_LIMIT = 20
# How often a process starts a run by itself; a kick (an entry just queued) starts one at once.
FLUSH_INTERVAL_SECONDS = 30.0
# Whether a run goes on a worker thread. Tests run it inline.
FLUSH_ASYNC = True

_LOCAL_SUFFIX = ".entry"
_LOCAL_LEASE = ".lease"
_CLOUD_ENTRIES = "github-outbox/entries/"
_CLOUD_LEASE = "github-outbox/lease"
_METADATA_BUDGET = "metadata-budget"
_REGISTRATION_BUDGET = "registration-budget"


class OutboxEntry(NamedTuple):
    """A file to copy to the log repository: what it is ("registration" or "metadata"), the path
    it lands at (fixed when it was queued), its commit message, its bytes, and its failed
    attempts so far (``MAX_ATTEMPTS``)."""

    kind: str
    path: str
    message: str
    content: bytes
    attempts: int = 0


class Delivery(Enum):
    """What became of an entry: delivered (or found at its path already), dropped for good, or
    not taken now, GitHub being unavailable: it stays, and every flusher backs off."""

    DELIVERED = "delivered"
    DROPPED = "dropped"
    UNAVAILABLE = "unavailable"


class FlushRun(NamedTuple):
    """What a run did: how many entries it delivered or dropped (given up ones too), and when the
    outbox may next be tried."""

    handled: int
    not_before: float


@dataclass
class Lease:
    """The outbox's lease as a run sees it: whether the run holds it and until when, and when the
    outbox may next be tried (what the run found, when it could not take it; what it leaves)."""

    held: bool
    until: float = 0.0
    not_before: float = 0.0


def outbox_dir() -> str:
    """The local outbox's folder (``FIDO_SERVER_GITHUB_OUTBOX_DIR``)."""

    return store_dir(*GITHUB_OUTBOX_STORE)


def encode_entry(entry: OutboxEntry) -> bytes:
    """An entry as the outbox keeps it: one line of JSON (kind, path, message, and its failed
    attempts once it has any), then the file's bytes."""

    header: dict[str, str | int] = {"kind": entry.kind, "path": entry.path, "message": entry.message}
    if entry.attempts:
        header["attempts"] = entry.attempts
    return json.dumps(header, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n" + entry.content


def decode_entry(data: bytes) -> OutboxEntry:
    """The entry ``encode_entry`` wrote; ValueError for anything else."""

    header, separator, content = data.partition(b"\n")
    if not separator:
        raise ValueError("an outbox entry has no header line")
    fields = json.loads(header.decode("ascii"))
    if not isinstance(fields, dict) or not all(isinstance(fields.get(key), str) for key in ("kind", "path", "message")):
        raise ValueError("an outbox entry's header is not one this server writes")
    # Entries queued before attempts were counted have none.
    attempts = fields.get("attempts", 0)
    if type(attempts) is not int or attempts < 0:
        raise ValueError("an outbox entry's attempts are not a count")
    return OutboxEntry(fields["kind"], fields["path"], fields["message"], content, attempts)


def _new_entry_id() -> str:
    """When the entry was queued, to the microsecond, and a random part: names sort in queue order."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{secrets.token_hex(4)}"


def _lease_times(data: bytes | None) -> tuple[float, float]:
    """The lease's ``until`` and ``notBefore``; none (0) for a lease that is absent or unreadable."""

    try:
        state = json.loads(data or b"{}")
    except ValueError:
        return 0.0, 0.0
    if not isinstance(state, dict):
        return 0.0, 0.0
    times = [state.get(key) for key in ("until", "notBefore")]
    until, not_before = (float(value) if isinstance(value, (int, float)) else 0.0 for value in times)
    return until, not_before


def _lease_bytes(until: float, not_before: float) -> bytes:
    return json.dumps({"until": until, "notBefore": not_before}).encode("ascii")


def _budget_used(data: bytes | None, day: str) -> tuple[int, int]:
    """The files and bytes the budget holds for ``day``; none for one absent, unreadable or another day's."""

    try:
        state = json.loads(data or b"{}")
    except ValueError:
        return 0, 0
    if not isinstance(state, dict) or state.get("day") != day:
        return 0, 0
    files, size = state.get("files"), state.get("bytes")
    if type(files) is not int or type(size) is not int or files < 0 or size < 0:
        return 0, 0
    return files, size


class _LocalOutbox:
    """The outbox in a local folder; its lease an ``flock``, which a stopped process gives up."""

    budget_prefix = "."

    def __init__(self, root: str) -> None:
        self.root = root

    def held(self) -> tuple[int, int]:
        count = size = 0
        try:
            with os.scandir(self.root) as entries:
                for item in entries:
                    if item.name.endswith(_LOCAL_SUFFIX):
                        count += 1
                        size += item.stat().st_size
        except FileNotFoundError:
            pass
        return count, size

    def write(self, entry_id: str, data: bytes) -> None:
        common.make_store_directory(self.root, self.root)
        common.replace_file(os.path.join(self.root, entry_id + _LOCAL_SUFFIX), data)

    def names(self) -> list[str]:
        try:
            return sorted(name for name in os.listdir(self.root) if name.endswith(_LOCAL_SUFFIX))
        except FileNotFoundError:
            return []

    def read(self, name: str) -> tuple[bytes | None, int]:
        try:
            with open(os.path.join(self.root, name), "rb") as handle:
                return handle.read(), 0
        except FileNotFoundError:
            return None, 0

    def rewrite(self, name: str, data: bytes, _generation: int) -> None:
        # Under the lease's flock no other flusher reads or removes an entry.
        common.replace_file(os.path.join(self.root, name), data)

    def remove(self, name: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(self.root, name))

    def update_budget(self, name: str, change: Callable[[bytes | None], bytes | None]) -> bool:
        common.make_store_directory(self.root, self.root)
        path = os.path.join(self.root, self.budget_prefix + name)
        with common.file_lock(path):
            written = change(self.read(self.budget_prefix + name)[0])
            if written is not None:
                common.replace_file(path, written)
        return True

    @contextlib.contextmanager
    def lease(self, now: float) -> Iterator[Lease]:
        common.make_store_directory(self.root, self.root)
        with open(os.path.join(self.root, _LOCAL_LEASE), "a+b") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield Lease(held=False)
                return
            try:
                handle.seek(0)
                _until, not_before = _lease_times(handle.read())
                if not_before > now:
                    yield Lease(held=False, not_before=not_before)
                    return
                lease = Lease(held=True, until=now + LEASE_SECONDS)
                try:
                    yield lease
                finally:
                    handle.truncate(0)
                    handle.write(_lease_bytes(0.0, lease.not_before))
                    handle.flush()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class _CloudOutbox:
    """The outbox in the bucket; its lease an object written only at the generation it was read at."""

    budget_prefix = "github-outbox/"

    def held(self) -> tuple[int, int]:
        stats = cloud.list_blob_stats(_CLOUD_ENTRIES)
        return len(stats), sum(stat.size for stat in stats)

    def write(self, entry_id: str, data: bytes) -> None:
        cloud.upload_bytes(_CLOUD_ENTRIES + entry_id, data, content_type="application/octet-stream")

    def names(self) -> list[str]:
        return sorted(cloud.list_blob_names(_CLOUD_ENTRIES))

    def read(self, name: str) -> tuple[bytes | None, int]:
        return cloud.download_bytes_with_generation(name)

    def rewrite(self, name: str, data: bytes, generation: int) -> None:
        # Only at the generation read: an entry a run that outlasted its lease removed meanwhile
        # stays removed.
        cloud.upload_bytes_if_generation(name, data, generation=generation, content_type="application/octet-stream")

    def remove(self, name: str) -> None:
        cloud.delete_blob(name)

    def update_budget(self, name: str, change: Callable[[bytes | None], bytes | None]) -> bool:
        # False when another request wrote the budget after it was read here.
        data, generation = self.read(self.budget_prefix + name)
        written = change(data)
        if written is None:
            return True
        return cloud.upload_bytes_if_generation(
            self.budget_prefix + name, written, generation=generation, content_type="application/json"
        )

    @contextlib.contextmanager
    def lease(self, now: float) -> Iterator[Lease]:
        data, generation = cloud.download_bytes_with_generation(_CLOUD_LEASE)
        until, not_before = _lease_times(data)
        if until > now or not_before > now:
            yield Lease(held=False, not_before=not_before)
            return
        # A lease past its time is taken over at the generation read: of two instances, one wins.
        lease = Lease(held=True, until=now + LEASE_SECONDS)
        written = cloud.upload_bytes_at_generation(
            _CLOUD_LEASE, _lease_bytes(lease.until, 0.0), generation=generation, content_type="application/json"
        )
        if written is None:
            yield Lease(held=False)
            return
        try:
            yield lease
        finally:
            _give_back(lease, written)


def _give_back(lease: Lease, generation: int) -> None:
    """Write the lease free again, with the time the outbox may next be tried, unless another
    flusher took it over meanwhile (this run outlasted it): that flusher's lease stands."""

    try:
        written = cloud.upload_bytes_at_generation(
            _CLOUD_LEASE, _lease_bytes(0.0, lease.not_before), generation=generation, content_type="application/json"
        )
    except Exception as exc:
        logger.warning("Could not give the credential log outbox's lease back; it lapses by itself: %s", exc)
        return
    if written is None:
        logger.info("Another flusher took the credential log outbox's lease over from a run that outlasted it")


def _backend() -> _LocalOutbox | _CloudOutbox:
    return _CloudOutbox() if common.using_gcs() else _LocalOutbox(outbox_dir())


def _held_or_none(backend: _LocalOutbox | _CloudOutbox, count: int) -> tuple[int, int] | None:
    """What the outbox holds (entries, bytes); None when it cannot be listed, with a warning."""

    try:
        return backend.held()
    except Exception as exc:
        logger.warning("Could not list the credential log outbox; queuing %d entries without its bound: %s", count, exc)
        return None


def enqueue(entries: Sequence[OutboxEntry]) -> int:
    """Queue ``entries`` for the log repository as far as the outbox's bound allows; how many were queued.

    The outbox is listed once for them all. An entry past the bound, or one that cannot be
    written, is dropped with a warning naming its path, never its content; when the listing
    fails the entries are written anyway. Never raises: whatever happens here, the request that
    queued them goes on.
    """

    if not entries:
        return 0
    backend = _backend()
    held = _held_or_none(backend, len(entries))
    queued = 0
    for entry in entries:
        try:
            data = encode_entry(entry)
            if held is not None:
                count, size = held
                if count >= MAX_ENTRIES or size + len(data) > MAX_BYTES:
                    logger.warning(
                        "The credential log outbox is full (%s entries, %s): dropped %s",
                        f"{count:,}",
                        common.describe_size(size),
                        log_text.client_text(entry.path),
                    )
                    continue
                held = (count + 1, size + len(data))
            backend.write(_new_entry_id(), data)
        except Exception as exc:
            logger.warning("Could not queue %s for the credential log: %s", log_text.client_text(entry.path), exc)
            continue
        queued += 1
    return queued


def take_metadata_budget(sizes: Sequence[int]) -> list[bool]:
    """Take today's (UTC) budget for uploaded metadata files of these sizes, in order: which it took
    (``METADATA_FILES_A_DAY``, ``METADATA_BYTES_A_DAY``; ``_take_budget``)."""

    return _take_budget(_METADATA_BUDGET, METADATA_FILES_A_DAY, METADATA_BYTES_A_DAY, sizes)


def _take_budget(name: str, most_files: int, most_bytes: int, sizes: Sequence[int]) -> list[bool]:
    """Take today's (UTC) budget ``name`` for files of these sizes, in order: which it took.

    A file is taken while the day's files and bytes stay within ``most_files`` and ``most_bytes``;
    one that does not fit is not, and a smaller one after it may be. A budget that takes none is
    not written. Read and written by compare-and-swap, and read again
    when another request wrote first, up to ``BUDGET_TRIES`` times; raises when it cannot be read
    or written, or past those tries.
    """

    day = _today()
    taken: list[bool] = []

    def change(data: bytes | None) -> bytes | None:
        taken.clear()
        files, size = _budget_used(data, day)
        for item in sizes:
            fits = files < most_files and size + item <= most_bytes
            if fits:
                files, size = files + 1, size + item
            taken.append(fits)
        return json.dumps({"day": day, "files": files, "bytes": size}).encode("ascii") if any(taken) else None

    backend = _backend()
    for _ in range(BUDGET_TRIES):
        if backend.update_budget(name, change):
            return taken
    raise RuntimeError(f"other requests wrote it first {BUDGET_TRIES} times in a row")


def _today() -> str:
    return datetime.fromtimestamp(time.time(), timezone.utc).date().isoformat()


def _registration_fits(size: int) -> bool:
    """Whether today's registration budget has room for an entry of ``size``; read only, and raises
    when it cannot be read."""

    backend = _backend()
    files, used = _budget_used(backend.read(backend.budget_prefix + _REGISTRATION_BUDGET)[0], _today())
    return files < REGISTRATIONS_A_DAY and used + size <= REGISTRATION_BYTES_A_DAY


def _delivered(deliver: Callable[[OutboxEntry], Delivery], entry: OutboxEntry) -> Delivery:
    """``deliver``'s answer; a registration past today's budget is dropped before it, and one delivered
    is counted after it. Raising (the budget unreadable too) is UNAVAILABLE: the entry stays."""

    registration = entry.kind == "registration"
    try:
        if registration and not _registration_fits(len(entry.content)):
            logger.warning(
                "Dropped %s from the credential log: today's budget of %s registrations and %s has no room for it;"
                " it starts again at 00:00 UTC",
                log_text.client_text(entry.path),
                f"{REGISTRATIONS_A_DAY:,}",
                common.describe_size(REGISTRATION_BYTES_A_DAY),
            )
            return Delivery.DROPPED
        delivery = deliver(entry)
    except Exception:
        logger.warning(
            "Could not deliver %s to the credential log; it stays queued", log_text.client_text(entry.path), exc_info=True
        )
        return Delivery.UNAVAILABLE
    if registration and delivery is Delivery.DELIVERED:
        try:
            _take_budget(_REGISTRATION_BUDGET, REGISTRATIONS_A_DAY, REGISTRATION_BYTES_A_DAY, [len(entry.content)])
        except Exception as exc:
            logger.warning(
                "Delivered %s to the credential log but could not count it in today's registration budget: %s",
                log_text.client_text(entry.path),
                exc,
            )
    return delivery


def _count_attempts(backend: _LocalOutbox | _CloudOutbox, passed_over: list[tuple[str, OutboxEntry, int]]) -> int:
    """A failed attempt for each entry GitHub did not take though it took a later one; an entry
    at ``MAX_ATTEMPTS`` is removed with a warning. How many were removed."""

    removed = 0
    for name, entry, generation in passed_over:
        attempts = entry.attempts + 1
        if attempts < MAX_ATTEMPTS:
            logger.info(
                "GitHub took a later entry but not %s (%d of %d attempts)", log_text.client_text(entry.path), attempts, MAX_ATTEMPTS
            )
            backend.rewrite(name, encode_entry(entry._replace(attempts=attempts)), generation)
            continue
        logger.warning(
            "Dropped %s from the credential log: GitHub did not take it in %d runs that delivered later entries",
            log_text.client_text(entry.path),
            attempts,
        )
        backend.remove(name)
        removed += 1
    return removed


def _deliver_due(
    backend: _LocalOutbox | _CloudOutbox, lease: Lease, deliver: Callable[[OutboxEntry], Delivery], limit: int
) -> int:
    handled = in_a_row = 0
    passed_over: list[tuple[str, OutboxEntry, int]] = []
    for name in backend.names():
        if handled >= limit or time.time() > lease.until - LEASE_MARGIN_SECONDS:
            break
        data, generation = backend.read(name)
        if data is None:
            continue
        try:
            entry = decode_entry(data)
        except ValueError:
            logger.warning("Removed %s from the credential log outbox: it is not an entry this server reads", name)
            backend.remove(name)
            continue
        delivery = _delivered(deliver, entry)
        if delivery is Delivery.UNAVAILABLE:
            passed_over.append((name, entry, generation))
            in_a_row += 1
            if in_a_row >= MAX_UNAVAILABLE_IN_A_ROW:
                break
            continue
        in_a_row = 0
        backend.remove(name)
        handled += 1
        if delivery is Delivery.DELIVERED:
            handled += _count_attempts(backend, passed_over)
            passed_over = []
    if passed_over:
        lease.not_before = time.time() + BACKOFF_SECONDS
    return handled


def flush(deliver: Callable[[OutboxEntry], Delivery], *, limit: int = RUN_LIMIT) -> FlushRun:
    """One run: take the outbox's lease, deliver its entries oldest first, and give the lease back.

    At most ``limit`` entries, and none started with less than ``LEASE_MARGIN_SECONDS`` of the
    lease left. An entry delivered or dropped is removed; one that does not decode is logged by
    name and removed. One GitHub cannot take (``deliver`` answers UNAVAILABLE, or raises) stays,
    and the run goes on to the next, up to ``MAX_UNAVAILABLE_IN_A_ROW`` in a row. When a later
    entry is delivered, each passed over before it is counted a failed attempt, kept with it,
    and given up at ``MAX_ATTEMPTS``; when none is, nothing is counted, and every flusher leaves
    the outbox for ``BACKOFF_SECONDS``. A passed-over entry keeps its place, first in the next run.
    Without the lease (another flusher holds it, or the outbox is backing off) a run does nothing,
    and with nothing queued it does not take the lease: a listing is all it costs.
    """

    backend = _backend()
    if not backend.names():
        return FlushRun(0, 0.0)
    with backend.lease(time.time()) as lease:
        if not lease.held:
            return FlushRun(0, lease.not_before)
        handled = _deliver_due(backend, lease, deliver, limit)
    return FlushRun(handled, lease.not_before)


@dataclass
class FlushState:
    """This process's flushing: when it last started a run, when the outbox may next be tried
    (as its last run found), the worker running one, and whether a kick came meanwhile."""

    last_run: float = 0.0
    not_before: float = 0.0
    worker: threading.Thread | None = None
    pending: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


FLUSH = FlushState()


def _run(deliver: Callable[[OutboxEntry], Delivery]) -> None:
    try:
        FLUSH.not_before = flush(deliver).not_before
    except Exception:
        logger.warning("Could not flush the credential log outbox", exc_info=True)


def _work(deliver: Callable[[OutboxEntry], Delivery]) -> None:
    while True:
        _run(deliver)
        with FLUSH.lock:
            if not FLUSH.pending or time.time() < FLUSH.not_before:
                FLUSH.pending = False
                FLUSH.worker = None
                return
            FLUSH.pending = False


def schedule_flush(deliver: Callable[[OutboxEntry], Delivery], *, kick: bool = False) -> None:
    """Start a run on a worker thread, unless this process started one within
    ``FLUSH_INTERVAL_SECONDS`` (a kick does not wait for that) or the outbox is backing off.

    Requests call it, so a run goes on while a request holds the CPU, which is when Cloud Run
    gives an instance any; a run that stalls between requests goes on at the next. A kick while
    a run is under way has the worker run once more after it, for what was queued meanwhile.
    """

    now = time.time()
    if now < FLUSH.not_before or (not kick and now - FLUSH.last_run < FLUSH_INTERVAL_SECONDS):
        return
    if not FLUSH_ASYNC:
        FLUSH.last_run = now
        _run(deliver)
        return
    with FLUSH.lock:
        if FLUSH.worker is not None and FLUSH.worker.is_alive():
            FLUSH.pending = FLUSH.pending or kick
            return
        FLUSH.last_run = now
        worker = threading.Thread(target=_work, args=(deliver,), name="credential-log-flush", daemon=True)
        FLUSH.worker = worker
    worker.start()
