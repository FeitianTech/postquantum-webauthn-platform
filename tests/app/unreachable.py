"""What a call leaves for the garbage collector: the reference cycles only a full collection frees."""
from __future__ import annotations

import gc
from collections.abc import Callable


def unreachable_after(call: Callable[[], object]) -> tuple[int, type[Exception] | None]:
    """How many objects a full collection finds unreachable after ``call()``, and the class of the
    error it raised, if any.

    The collector is off during the call, so nothing it left is freed before it is counted, and is
    restored as it was. The error is dropped first, as a route drops a refusal once it has answered:
    what it still holds then is held only by a cycle.
    """

    gc.collect()
    enabled = gc.isenabled()
    gc.disable()
    try:
        raised: type[Exception] | None = None
        try:
            call()
        except Exception as exc:
            raised = type(exc)
        return gc.collect(), raised
    finally:
        if enabled:
            gc.enable()
