"""The credential log's outbox: the files waiting to be copied to the log repository on GitHub.

A registration's log entry and an uploaded metadata file are queued here once their save
succeeded (``enqueue``), each with the path it lands at in the repository, fixed then, and
delivered later by ``flush``. One flusher at a time holds the outbox's lease: GitHub takes new
files one at a time (its create-file endpoint refuses calls made in parallel), and when it cannot
take one every flusher backs off together. A delivery made twice finds its file at its path, so
an entry is delivered at least once and never becomes two files.

Locally the outbox is a folder (``FIDO_SERVER_GITHUB_OUTBOX_DIR``, else ``instance/github-outbox``):
each entry ``<id>.entry``, and the lease an ``flock`` on ``.lease``, which also keeps when the
outbox may next be tried. docs/STORAGE.md has the rules.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import secrets
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import NamedTuple

from ..config.paths import GITHUB_OUTBOX_STORE, store_dir
from . import common

logger = logging.getLogger(__name__)

__all__ = [
    "Delivery",
    "FlushRun",
    "Lease",
    "OutboxEntry",
    "decode_entry",
    "encode_entry",
    "enqueue",
    "flush",
    "outbox_dir",
]

# The outbox's bound: an entry past either is dropped with a warning.
MAX_ENTRIES = 1_000
MAX_BYTES = 256 * 1024 * 1024
# How long a run holds the lease, and how much of it must be left to start a delivery: a run
# that stalled past its lease (a throttled CPU) starts nothing another flusher may be doing.
LEASE_SECONDS = 300.0
LEASE_MARGIN_SECONDS = 60.0
# How long every flusher leaves the outbox after GitHub could not take a delivery.
BACKOFF_SECONDS = 300.0
# The most entries one run delivers.
RUN_LIMIT = 20

_LOCAL_SUFFIX = ".entry"
_LOCAL_LEASE = ".lease"


class OutboxEntry(NamedTuple):
    """A file to copy to the log repository: what it is ("registration" or "metadata"), the path
    it lands at (fixed when it was queued), its commit message and its bytes."""

    kind: str
    path: str
    message: str
    content: bytes


class Delivery(Enum):
    """What became of an entry: delivered (or found at its path already), dropped for good, or
    not taken now, GitHub being unavailable: it stays, and every flusher backs off."""

    DELIVERED = "delivered"
    DROPPED = "dropped"
    UNAVAILABLE = "unavailable"


class FlushRun(NamedTuple):
    """What a run did: how many entries it delivered or dropped, and when the outbox may next be tried."""

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
    """An entry as the outbox keeps it: one line of JSON (kind, path, message), then the file's bytes."""

    header = {"kind": entry.kind, "path": entry.path, "message": entry.message}
    return json.dumps(header, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n" + entry.content


def decode_entry(data: bytes) -> OutboxEntry:
    """The entry ``encode_entry`` wrote; ValueError for anything else."""

    header, separator, content = data.partition(b"\n")
    if not separator:
        raise ValueError("an outbox entry has no header line")
    fields = json.loads(header.decode("ascii"))
    if not isinstance(fields, dict) or not all(isinstance(fields.get(key), str) for key in ("kind", "path", "message")):
        raise ValueError("an outbox entry's header is not one this server writes")
    return OutboxEntry(fields["kind"], fields["path"], fields["message"], content)


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


class _LocalOutbox:
    """The outbox in a local folder; its lease an ``flock``, which a stopped process gives up."""

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
        # Listed under the lease, which made the folder.
        return sorted(name for name in os.listdir(self.root) if name.endswith(_LOCAL_SUFFIX))

    def read(self, name: str) -> bytes | None:
        try:
            with open(os.path.join(self.root, name), "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def remove(self, name: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(self.root, name))

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


def _backend() -> _LocalOutbox:
    return _LocalOutbox(outbox_dir())


def _held_or_none(backend: _LocalOutbox, count: int) -> tuple[int, int] | None:
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
                        entry.path,
                    )
                    continue
                held = (count + 1, size + len(data))
            backend.write(_new_entry_id(), data)
        except Exception as exc:
            logger.warning("Could not queue %s for the credential log: %s", entry.path, exc)
            continue
        queued += 1
    return queued


def _delivered(deliver: Callable[[OutboxEntry], Delivery], entry: OutboxEntry) -> Delivery:
    try:
        return deliver(entry)
    except Exception:
        logger.warning("Could not deliver %s to the credential log; it stays queued", entry.path, exc_info=True)
        return Delivery.UNAVAILABLE


def _deliver_due(backend: _LocalOutbox, lease: Lease, deliver: Callable[[OutboxEntry], Delivery], limit: int) -> int:
    handled = 0
    for name in backend.names():
        if handled >= limit or time.time() > lease.until - LEASE_MARGIN_SECONDS:
            break
        data = backend.read(name)
        if data is None:
            continue
        try:
            entry = decode_entry(data)
        except ValueError:
            logger.warning("Removed %s from the credential log outbox: it is not an entry this server reads", name)
            backend.remove(name)
            continue
        if _delivered(deliver, entry) is Delivery.UNAVAILABLE:
            lease.not_before = time.time() + BACKOFF_SECONDS
            break
        backend.remove(name)
        handled += 1
    return handled


def flush(deliver: Callable[[OutboxEntry], Delivery], *, limit: int = RUN_LIMIT) -> FlushRun:
    """One run: take the outbox's lease, deliver its entries oldest first, and give the lease back.

    At most ``limit`` entries, and none started with less than ``LEASE_MARGIN_SECONDS`` of the
    lease left. An entry delivered or dropped is removed; one that does not decode is logged by
    name and removed. When GitHub cannot take one (``deliver`` answers UNAVAILABLE, or raises),
    it stays, the run stops, and every flusher leaves the outbox for ``BACKOFF_SECONDS``.
    Without the lease (another flusher holds it, or the outbox is backing off) a run does nothing.
    """

    backend = _backend()
    with backend.lease(time.time()) as lease:
        if not lease.held:
            return FlushRun(0, lease.not_before)
        handled = _deliver_due(backend, lease, deliver, limit)
    return FlushRun(handled, lease.not_before)
