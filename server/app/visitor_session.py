"""The visitor session: the namespace a visitor's uploads and credentials are stored under.

Its id lives in a long-lived cookie of its own, signed with the app's secret
(``COOKIE_SALT``), so a caller can never point itself at another visitor's
namespace; the Flask session does not hold it. Page views refresh the namespace's last-access marker
(``note_activity``), at most once per ``TOUCH_THROTTLE_SECONDS`` in each process;
namespaces idle for ``INACTIVE_AGE`` are removed by one sweep, on both storage
backends, at most every ``CLEANUP_INTERVAL`` (``schedule_cleanup``).
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta

from flask import (
    after_this_request,
    current_app,
    g,
    has_request_context,
    request,
    session,
)
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .storage import common as storage_common
from .storage import session_metadata

logger = logging.getLogger(__name__)

COOKIE_NAME = "fido.mds.session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
# The cookie is signed again (and its year starts again) when it is older than this.
COOKIE_REFRESH_SECONDS = 60 * 60 * 24
# Salt for the recovery cookie; the key is the app's ``secret_key``.
COOKIE_SALT = "fido.mds.session-cookie.v1"
INACTIVE_AGE = timedelta(days=14)
# Page views refresh the session's last-access marker at most this often; the
# marker only needs to be accurate relative to the 14-day inactivity cutoff.
TOUCH_THROTTLE_SECONDS = 1800.0
# Past this many namespaces remembered, the ones outside the throttle window are forgotten.
_TOUCHES_KEPT = 10_000
# How often inactive sessions are swept, and whether the sweep runs on a worker
# thread. Tests set these to override them.
CLEANUP_INTERVAL = timedelta(hours=6)
CLEANUP_ASYNC = True


@dataclass
class CleanupState:
    """When the inactive-session sweep last ran, and the worker running it."""

    last_run: float = 0.0
    worker: threading.Thread | None = None
    pending: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


CLEANUP = CleanupState()


@dataclass
class TouchState:
    """When this process last refreshed each namespace's last-access marker."""

    last: dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


TOUCHES = TouchState()


def _due_for_touch(session_id: str, now: float) -> bool:
    """Whether the namespace's marker is due a refresh; if so, it counts as refreshed now."""

    with TOUCHES.lock:
        last = TOUCHES.last.get(session_id)
        if last is not None and 0 <= now - last < TOUCH_THROTTLE_SECONDS:
            return False
        if len(TOUCHES.last) >= _TOUCHES_KEPT:
            cutoff = now - TOUCH_THROTTLE_SECONDS
            TOUCHES.last = {key: value for key, value in TOUCHES.last.items() if value >= cutoff}
        TOUCHES.last[session_id] = now
        return True


def _touch_last_access(session_id: str) -> None:
    try:
        session_metadata.touch_last_access(session_id)
    except Exception:
        pass


def _resolve_last_access(session_id: str) -> float | None:
    try:
        return session_metadata.resolve_last_access(session_id)
    except Exception:
        return None


def _maybe_cleanup(now: float | None = None) -> None:
    current_time = now or time.time()
    with CLEANUP.lock:
        if current_time - CLEANUP.last_run < CLEANUP_INTERVAL.total_seconds():
            return
        CLEANUP.last_run = current_time

    cutoff = current_time - INACTIVE_AGE.total_seconds()

    try:
        sessions = session_metadata.list_sessions()
    except Exception:
        return

    for session_id in sessions:
        last_access = _resolve_last_access(session_id)
        if last_access is None or last_access >= cutoff:
            continue

        try:
            session_metadata.delete_session(session_id)
        except Exception as exc:
            logger.warning(
                "Failed to remove inactive metadata session %s: %s", session_id, exc
            )


def _run_cleanup_worker() -> None:
    while True:
        try:
            _maybe_cleanup()
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning(
                "Unexpected failure while cleaning inactive metadata sessions: %s",
                exc,
                exc_info=True,
            )

        with CLEANUP.lock:
            if CLEANUP.pending:
                CLEANUP.pending = False
                continue

            CLEANUP.worker = None
            return


def schedule_cleanup() -> None:
    """Sweep inactive sessions, on a worker thread, unless one ran within ``CLEANUP_INTERVAL``."""

    current_time = time.time()
    if current_time - CLEANUP.last_run < CLEANUP_INTERVAL.total_seconds():
        return

    if not CLEANUP_ASYNC:
        _maybe_cleanup(now=current_time)
        return

    worker: threading.Thread | None = None

    with CLEANUP.lock:
        if CLEANUP.worker is not None and CLEANUP.worker.is_alive():
            CLEANUP.pending = True
            return

        worker = threading.Thread(
            target=_run_cleanup_worker,
            name="session-metadata-cleanup",
            daemon=True,
        )
        CLEANUP.worker = worker

    try:
        worker.start()
    except RuntimeError:  # pragma: no cover - defensive fallback
        with CLEANUP.lock:
            if CLEANUP.worker is worker:
                CLEANUP.worker = None
                CLEANUP.pending = False
        _maybe_cleanup(now=current_time)


def _serializer() -> URLSafeTimedSerializer | None:
    secret = current_app.secret_key
    return URLSafeTimedSerializer(secret, salt=COOKIE_SALT) if secret else None


def _read_cookie() -> tuple[str | None, float]:
    """The namespace the request's cookie names, and when it was signed.

    None when there is no cookie, or one this server did not sign.
    Handing back a bare namespace name would let anyone who can set a cookie
    point themselves at another visitor's namespace, so the value is signed with
    the application secret and checked here on the way back in.
    """

    raw_cookie = request.cookies.get(COOKIE_NAME)
    serializer = _serializer()
    if not isinstance(raw_cookie, str) or not raw_cookie or serializer is None:
        return None, 0.0
    try:
        unsealed, signed_at = serializer.loads(raw_cookie, max_age=COOKIE_MAX_AGE, return_timestamp=True)
    except BadSignature:
        # Also covers SignatureExpired / BadTimeSignature.
        return None, 0.0
    except Exception:
        return None, 0.0
    return storage_common.normalise_session_id(unsealed), signed_at.timestamp()


def _set_cookie(identifier: str) -> None:
    serializer = _serializer()
    if serializer is None:
        return
    sealed = serializer.dumps(identifier)
    # Secure as the session cookie is; Lax, like it: the metadata upload is a
    # multipart form, which another site could post in the visitor's namespace
    # were the cookie sent cross-site.
    secure = bool(current_app.config.get("SESSION_COOKIE_SECURE"))

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            COOKIE_NAME,
            sealed,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite="Lax",
            path="/",
        )
        return response


def current_id(*, create: bool = False) -> str | None:
    """The visitor's namespace, from its signed cookie; with ``create``, a new one if none.

    The cookie is set when a namespace is minted, and again when it was signed
    more than ``COOKIE_REFRESH_SECONDS`` ago, so a visitor who keeps coming back
    keeps their namespace. The id is kept for the rest of the request, so every
    store a request writes uses one namespace.
    """

    if not has_request_context():
        return None

    cached = g.get("_visitor_namespace")
    if cached:
        return cached

    identifier, signed_at = _read_cookie()
    if identifier:
        if time.time() - signed_at > COOKIE_REFRESH_SECONDS:
            _set_cookie(identifier)
    elif create:
        identifier = secrets.token_urlsafe(32)
        # A brand-new namespace has nothing stored yet, so it does not need a
        # last-access marker until it writes data (writes refresh it themselves).
        g._mds_session_new = identifier
        _set_cookie(identifier)
    else:
        return None

    g._visitor_namespace = identifier
    note_activity(identifier)
    return identifier


def ensure_id() -> str:
    """The visitor's session id, created when the visitor has none; the session is made permanent."""

    identifier = current_id(create=True)
    if not identifier:
        raise RuntimeError("Unable to establish metadata session identifier.")
    if has_request_context():
        session.permanent = True
    return identifier


def note_activity(session_id: str) -> None:
    """Refresh the session's last-access marker, throttled, and schedule the sweep."""

    normalised = storage_common.normalise_session_id(session_id)
    if not normalised:
        return

    # Refreshing the marker is a storage write, so it is done at most once per
    # throttle window per namespace. A namespace this request minted holds
    # nothing yet: it needs no marker until it writes data (writes refresh it).
    minted = has_request_context() and getattr(g, "_mds_session_new", None) == normalised
    if _due_for_touch(normalised, time.time()) and not minted:
        _touch_last_access(normalised)
    schedule_cleanup()
