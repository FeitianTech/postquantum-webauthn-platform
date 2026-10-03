"""A lock stand-in for the MDS caches' tests (``mds.cache``, ``mds.verifier``).

Each cache is checked once without its lock and again under it, since another
thread may have filled it while this one waited. ``FillingLock`` makes that
wait happen: as it is taken, it does what the thread that held it first did.
"""
from __future__ import annotations

import threading
from collections.abc import Callable


class FillingLock:
    def __init__(self, fill: Callable[[], None]) -> None:
        self._fill = fill
        self._lock = threading.RLock()

    def __enter__(self):
        self._fill()
        return self._lock.__enter__()

    def __exit__(self, *exc_info):
        return self._lock.__exit__(*exc_info)
