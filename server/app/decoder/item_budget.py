"""How many items the codec reads for one request: the budget that bounds what a request costs.

Each item the codec reads costs a node, its findings and its place in the
answer, and the decoder reads an input more than once: ``decode/readings.py``
tries each reading in turn and checks which others read the input whole too,
so a plain CBOR item is parsed five times, and one after a CTAP byte eight. The
codec's two entries, ``decode/text.decode_payload_text`` and
``encode/text.encode_payload_text``, therefore each read under one budget
(``limit``): every CBOR item ``decode/cbor_parser`` builds, every JSON value
``decode/json_input`` reads and every EDN item ``edn/reader`` reads is counted
against it, over all the readings of one request, so that no input multiplies
its cost by being read again.

The decoder's checks of its own output (its EDN text read back, a CTAP view
rebuilt) are not counted (``unmetered``): they re-read what counted reads
built, and a refusal there would name an offset in text the decoder wrote.

Past the limit, the read that ran out raises ``ItemLimitError``: the limit, and
the offset and path where that read was. A reading that fails is only "not
this reading" to the decoder, which goes on to the next, so whatever catches
the error on the way, ``limit`` raises the first one again when its block ends:
a request over the budget is refused, never answered with less.

The default, 20,000, from measurement: the largest real inputs read 72 items
(an ML-DSA-87 attestation object with its chain), 1,888 (a getInfo holding
every CTAP 2.2 member) and 3,114 (a makeCredential request excluding 64
credentials), and at 20,000 the costliest request, lenient input that writes a
finding for each item, takes 0.2 to 0.4 s and about 30 MB (docs/DECODER.md).
"""
from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator

DEFAULT_MAX_ITEMS = 20_000


class ItemLimitError(ValueError):
    """More items than the budget allows: the limit, and where the read that ran out was.

    The offset and path are what that read knows: JSON gives no offset, EDN no path.
    """

    def __init__(self, limit: int, offset: int | None, path: str | None) -> None:
        self.limit, self.offset, self.path = limit, offset, path
        if offset is None:
            where = path
        elif path is None:
            where = f"offset {offset}"
        else:
            where = f"offset {offset} ({path})"
        super().__init__(
            f"Too many items at {where}: the codec reads at most {limit} items (CBOR items, JSON values, "
            "EDN items) for one request, over all its readings of the input"
        )


class Budget:
    """One request's count: how many items it may read, how many it has read, and its first refusal."""

    __slots__ = ("limit", "used", "refusal")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.refusal: ItemLimitError | None = None

    def charge(self, offset: int | None, path: str | None) -> None:
        """Count one item, read at ``offset`` and ``path``; past the limit, refuse it there."""

        self.used += 1
        if self.used > self.limit:
            refusal = ItemLimitError(self.limit, offset, path)
            if self.refusal is None:
                self.refusal = refusal
            raise refusal


_CURRENT: contextvars.ContextVar[Budget | None] = contextvars.ContextVar("codec_item_budget", default=None)


def current() -> Budget | None:
    """The budget the reads in progress count against; ``None`` outside the codec's entries."""

    return _CURRENT.get()


@contextlib.contextmanager
def limit(max_items: int) -> Iterator[Budget]:
    """Read under a budget of ``max_items``; when the block ends, raise its first refusal, whatever caught it."""

    budget = Budget(max_items)
    token = _CURRENT.set(budget)
    try:
        yield budget
    except Exception:
        # The error that ends the block can be another one, raised by a reading
        # that went on without the read that ran out.
        if budget.refusal is not None:
            raise budget.refusal from None
        raise
    finally:
        _CURRENT.reset(token)
    if budget.refusal is not None:
        raise budget.refusal


@contextlib.contextmanager
def unmetered() -> Iterator[None]:
    """Read without counting: for the decoder's checks of its own output, which re-read what was counted."""

    token = _CURRENT.set(None)
    try:
        yield
    finally:
        _CURRENT.reset(token)
