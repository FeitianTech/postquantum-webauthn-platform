"""Session cleanup worker and scheduling helpers."""
from __future__ import annotations

import threading
import time

from .. import session_metadata_store
from ..config import app
from . import env_runtime
from . import runtime_state as _state
from .runtime_state import _SESSION_METADATA_INACTIVE_AGE


def _touch_session_last_access(session_id: str) -> None:
    try:
        session_metadata_store.touch_last_access(session_id)
    except Exception:
        pass


def _resolve_session_last_access(session_id: str) -> float | None:
    try:
        return session_metadata_store.resolve_last_access(session_id)
    except Exception:
        return None


def _maybe_cleanup_inactive_sessions(now: float | None = None) -> None:
    current_time = now or time.time()
    with _state._session_cleanup_lock:
        if current_time - _state._session_metadata_last_cleanup < env_runtime._SESSION_METADATA_CLEANUP_INTERVAL.total_seconds():
            return
        _state._session_metadata_last_cleanup = current_time

    cutoff = current_time - _SESSION_METADATA_INACTIVE_AGE.total_seconds()

    try:
        sessions = session_metadata_store.list_sessions()
    except Exception:
        return

    for session_id in sessions:
        last_access = _resolve_session_last_access(session_id)
        if last_access is None or last_access >= cutoff:
            continue

        try:
            session_metadata_store.delete_session(session_id)
        except Exception as exc:
            app.logger.warning(
                "Failed to remove inactive metadata session %s: %s", session_id, exc
            )


def _run_inactive_session_cleanup_worker() -> None:
    while True:
        try:
            _maybe_cleanup_inactive_sessions()
        except Exception as exc:  # pragma: no cover - defensive logging
            app.logger.warning(
                "Unexpected failure while cleaning inactive metadata sessions: %s",
                exc,
                exc_info=True,
            )

        with _state._session_cleanup_lock:
            if _state._session_cleanup_pending:
                _state._session_cleanup_pending = False
                continue

            _state._session_cleanup_worker = None
            return


def _schedule_inactive_session_cleanup() -> None:
    current_time = time.time()
    if (
        current_time - _state._session_metadata_last_cleanup
        < env_runtime._SESSION_METADATA_CLEANUP_INTERVAL.total_seconds()
    ):
        return

    if not env_runtime._cleanup_async_enabled():
        _maybe_cleanup_inactive_sessions(now=current_time)
        return

    worker: threading.Thread | None = None

    with _state._session_cleanup_lock:
        if _state._session_cleanup_worker is not None and _state._session_cleanup_worker.is_alive():
            _state._session_cleanup_pending = True
            return

        worker = threading.Thread(
            target=_run_inactive_session_cleanup_worker,
            name="session-metadata-cleanup",
            daemon=True,
        )
        _state._session_cleanup_worker = worker

    try:
        worker.start()
    except RuntimeError:  # pragma: no cover - defensive fallback
        with _state._session_cleanup_lock:
            if _state._session_cleanup_worker is worker:
                _state._session_cleanup_worker = None
                _state._session_cleanup_pending = False
        _maybe_cleanup_inactive_sessions(now=current_time)
