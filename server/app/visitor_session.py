"""The visitor session: the namespace a visitor's uploads and credentials are stored under.

Its id lives in the signed Flask session and, for a returning visitor whose
session has expired, in a long-lived recovery cookie signed with the app's
secret (``COOKIE_SALT``), so a caller can never point itself at another
visitor's namespace. Page views refresh the namespace's last-access marker
(``note_activity``), at most once per request and per ``TOUCH_THROTTLE_SECONDS``;
namespaces idle for ``INACTIVE_AGE`` are removed by one sweep, on both storage
backends, at most every ``CLEANUP_INTERVAL`` (``schedule_cleanup``).
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from flask import (
    after_this_request,
    current_app,
    g,
    has_request_context,
    request,
    session,
)
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .storage import session_metadata

logger = logging.getLogger(__name__)

SESSION_KEY = "fido.mds.session"
COOKIE_NAME = "fido.mds.session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
# Salt for the recovery cookie; the key is the app's ``secret_key``.
COOKIE_SALT = "fido.mds.session-cookie.v1"
INACTIVE_AGE = timedelta(days=14)
# Page views refresh the session's last-access marker at most this often; the
# marker only needs to be accurate relative to the 14-day inactivity cutoff.
TOUCH_KEY = "fido.mds.touched_at"
TOUCH_THROTTLE_SECONDS = 1800.0
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


def normalise_id(value: Any) -> str | None:
    """``value`` as a session id: a string that names no path; None otherwise."""

    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


def _schedule_cookie(identifier: str) -> None:
    if not has_request_context():
        return

    normalised = normalise_id(identifier)
    if not normalised:
        return

    note_activity(normalised)

    secure = bool(request.is_secure)
    cookie_path = "/"
    # Lax, like the session cookie: the metadata upload is a multipart form,
    # which another site could post in the visitor's namespace were the cookie
    # sent cross-site.
    samesite = "Lax"

    if getattr(g, "_session_metadata_cookie", None) == normalised:
        return

    # The recovery cookie is client storage.  Handing back a bare namespace name
    # lets anyone who can set a cookie point themselves at another visitor's
    # namespace, so the value that leaves the server is signed with the
    # application secret and the signature is re-checked on the way back in.
    secret = current_app.secret_key
    if not secret:
        return

    sealed = URLSafeTimedSerializer(secret, salt=COOKIE_SALT).dumps(normalised)

    g._session_metadata_cookie = normalised

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            COOKIE_NAME,
            sealed,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path=cookie_path,
        )
        return response


def current_id(*, create: bool = False) -> str | None:
    """The visitor's session id; with ``create``, a new one when the visitor has none."""

    if not has_request_context():
        return None

    # The signed Flask session is authoritative.  It is authenticated with the
    # application secret, so a caller cannot point it at somebody else's
    # namespace.
    existing = session.get(SESSION_KEY)
    if isinstance(existing, str):
        identifier = normalise_id(existing)
        if identifier:
            session[SESSION_KEY] = identifier
            _schedule_cookie(identifier)
            return identifier

    # Otherwise fall back to the long-lived recovery cookie, so a returning
    # visitor keeps their namespace after the (much shorter lived) Flask session
    # has expired.  Only a cookie this server signed is honoured; a forged or
    # replayed-from-elsewhere value is ignored and a fresh namespace is minted
    # instead, which is what stops one caller reading another's stored metadata
    # and credential artifacts.
    cookie_identifier = None
    raw_cookie = request.cookies.get(COOKIE_NAME)
    secret = current_app.secret_key
    if isinstance(raw_cookie, str) and raw_cookie and secret:
        try:
            unsealed = URLSafeTimedSerializer(secret, salt=COOKIE_SALT).loads(raw_cookie, max_age=COOKIE_MAX_AGE)
        except BadSignature:
            # Also covers SignatureExpired / BadTimeSignature.
            unsealed = None
        except Exception:
            unsealed = None
        cookie_identifier = normalise_id(unsealed)

    if cookie_identifier:
        session[SESSION_KEY] = cookie_identifier
        _schedule_cookie(cookie_identifier)
        return cookie_identifier

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[SESSION_KEY] = identifier
    # A brand-new session has nothing stored yet, so it does not need a
    # last-access marker until it writes data (writes refresh it themselves).
    g._mds_session_new = identifier
    _schedule_cookie(identifier)
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

    normalised = normalise_id(session_id)
    if not normalised:
        return

    if has_request_context():
        # Refreshing the marker is a storage write, so do it at most once per
        # request and at most once per throttle window per session.
        if getattr(g, "_mds_session_touched", None) == normalised:
            return
        g._mds_session_touched = normalised

        now = time.time()
        if getattr(g, "_mds_session_new", None) == normalised:
            session[TOUCH_KEY] = now
            schedule_cleanup()
            return

        throttle = TOUCH_THROTTLE_SECONDS
        last_touch = session.get(TOUCH_KEY)
        if isinstance(last_touch, (int, float)) and 0 <= now - last_touch < throttle:
            schedule_cleanup()
            return
        session[TOUCH_KEY] = now

    _touch_last_access(normalised)
    schedule_cleanup()
