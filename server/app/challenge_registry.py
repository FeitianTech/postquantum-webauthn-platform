"""Single-use tracking for WebAuthn ceremony challenges.

Why this exists server-side
---------------------------
Flask sessions in this app are client-side signed cookies. Popping the ceremony
state out of the session on ``/complete`` does NOT stop a replay: the caller can
simply resend the earlier cookie, which still carries the state and is still
validly signed. The only thing that can refuse a second use is a record the
server keeps itself, so every ``/complete`` consumes its challenge here.

Two rules together make a challenge single-use:

1. **Freshness.** ``/begin`` stamps the state with ``issued_at`` (inside the
   signed cookie, so it cannot be forged). A state older than the TTL is
   refused outright.
2. **Consumption.** Within that window the challenge is recorded as consumed on
   first use and refused thereafter. Records are retained for at least the
   TTL, so a record can only be evicted once rule 1 already refuses its state.

Limitation: in-process only
---------------------------
:class:`InMemoryChallengeRegistry` protects a single process. Cloud Run runs up
to ``maxScale`` instances (and gunicorn may run several workers), and a replay
routed to a different instance/worker than the original ``/complete`` will not
be detected. Swapping in a shared store only requires another
:class:`ChallengeRegistry` implementation passed to
:func:`set_challenge_registry`.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional
from collections.abc import Callable, Mapping, MutableMapping

__all__ = [
    "CHALLENGE_EXPIRED",
    "CHALLENGE_FRESH",
    "CHALLENGE_REPLAYED",
    "ChallengeRegistry",
    "InMemoryChallengeRegistry",
    "challenge_ttl_seconds",
    "consume_ceremony_state",
    "get_challenge_registry",
    "set_challenge_registry",
    "stamp_ceremony_state",
]

#: The challenge had not been used before and is now consumed.
CHALLENGE_FRESH = "fresh"
#: The challenge had already been consumed by an earlier ``/complete``.
CHALLENGE_REPLAYED = "replayed"
#: The state is older than the TTL, or carries no usable ``issued_at`` stamp.
CHALLENGE_EXPIRED = "expired"

ISSUED_AT_KEY = "issued_at"

_DEFAULT_TTL_SECONDS = 10 * 60
# Tolerated wall-clock disagreement between the instance that issued a state
# and the one completing it.
_CLOCK_SKEW_SECONDS = 60


def challenge_ttl_seconds() -> int:
    """How long an issued challenge stays usable (``FIDO_SERVER_CHALLENGE_TTL_SECONDS``)."""

    raw = os.environ.get("FIDO_SERVER_CHALLENGE_TTL_SECONDS")
    if raw:
        try:
            value = int(raw)
        except ValueError:
            return _DEFAULT_TTL_SECONDS
        if value > 0:
            return value
    return _DEFAULT_TTL_SECONDS


class ChallengeRegistry:
    """Narrow interface: atomically consume a challenge exactly once."""

    def consume(self, challenge: str) -> bool:
        """Mark ``challenge`` consumed. Return ``False`` if it already was."""

        raise NotImplementedError


class InMemoryChallengeRegistry(ChallengeRegistry):
    """Thread-safe, in-process registry whose records expire after ``ttl_seconds``.

    See the module docstring: this does not protect across processes.
    """

    def __init__(
        self,
        ttl_seconds: Optional[float] = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # By default a record outlives the window in which its state could
        # still be accepted, skew included.
        if ttl_seconds is None:
            ttl_seconds = challenge_ttl_seconds() + _CLOCK_SKEW_SECONDS
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._expiry_by_challenge: dict[str, float] = {}

    def consume(self, challenge: str) -> bool:
        now = self._clock()
        with self._lock:
            self._purge(now)
            if challenge in self._expiry_by_challenge:
                return False
            self._expiry_by_challenge[challenge] = now + self._ttl
            return True

    def __len__(self) -> int:
        with self._lock:
            self._purge(self._clock())
            return len(self._expiry_by_challenge)

    def _purge(self, now: float) -> None:
        expired = [key for key, expiry in self._expiry_by_challenge.items() if expiry <= now]
        for key in expired:
            del self._expiry_by_challenge[key]


_registry: ChallengeRegistry = InMemoryChallengeRegistry()


def get_challenge_registry() -> ChallengeRegistry:
    return _registry


def set_challenge_registry(registry: ChallengeRegistry) -> None:
    global _registry
    _registry = registry


def stamp_ceremony_state(state: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Record when a ceremony state was issued. Call from every ``/begin``."""

    state[ISSUED_AT_KEY] = time.time()
    return state


def consume_ceremony_state(state: Any) -> str:
    """Consume the challenge in ``state`` and report what was found.

    Returns :data:`CHALLENGE_FRESH`, :data:`CHALLENGE_REPLAYED` or
    :data:`CHALLENGE_EXPIRED`. Only a ``fresh`` result permits the ceremony to
    be trusted. The challenge is consumed whether or not the ceremony then
    goes on to verify, so a failed attempt cannot be retried either.
    """

    if not isinstance(state, Mapping):
        return CHALLENGE_EXPIRED
    challenge = state.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        return CHALLENGE_EXPIRED

    issued_at = state.get(ISSUED_AT_KEY)
    fresh_in_time = (
        isinstance(issued_at, (int, float))
        and not isinstance(issued_at, bool)
        and -_CLOCK_SKEW_SECONDS <= time.time() - issued_at <= challenge_ttl_seconds()
    )

    # Consume even an expired challenge, so no path leaves it reusable.
    first_use = get_challenge_registry().consume(challenge)
    if not fresh_in_time:
        return CHALLENGE_EXPIRED
    return CHALLENGE_FRESH if first_use else CHALLENGE_REPLAYED
