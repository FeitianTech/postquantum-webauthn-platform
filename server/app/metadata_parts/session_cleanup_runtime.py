"""Session cleanup worker and scheduling helpers."""
from __future__ import annotations


def _touch_session_last_access(session_id: str) -> None:
    try:
        session_metadata_store.touch_last_access(session_id)
    except Exception:
        pass


def _resolve_session_last_access(session_id: str) -> Optional[float]:
    try:
        return session_metadata_store.resolve_last_access(session_id)
    except Exception:
        return None


def _maybe_cleanup_inactive_sessions(now: Optional[float] = None) -> None:
    global _session_metadata_last_cleanup

    current_time = now or time.time()
    if current_time - _session_metadata_last_cleanup < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds():
        return

    _session_metadata_last_cleanup = current_time
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
    global _session_cleanup_worker, _session_cleanup_pending

    while True:
        try:
            _maybe_cleanup_inactive_sessions()
        except Exception as exc:  # pragma: no cover - defensive logging
            app.logger.warning(
                "Unexpected failure while cleaning inactive metadata sessions: %s",
                exc,
                exc_info=True,
            )

        with _session_cleanup_lock:
            if _session_cleanup_pending:
                _session_cleanup_pending = False
                continue

            _session_cleanup_worker = None
            return


def _schedule_inactive_session_cleanup() -> None:
    global _session_cleanup_worker, _session_cleanup_pending

    current_time = time.time()
    if (
        current_time - _session_metadata_last_cleanup
        < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds()
    ):
        return

    if not _cleanup_async_enabled():
        _maybe_cleanup_inactive_sessions(now=current_time)
        return

    worker: Optional[threading.Thread] = None

    with _session_cleanup_lock:
        if _session_cleanup_worker is not None and _session_cleanup_worker.is_alive():
            _session_cleanup_pending = True
            return

        worker = threading.Thread(
            target=_run_inactive_session_cleanup_worker,
            name="session-metadata-cleanup",
            daemon=True,
        )
        _session_cleanup_worker = worker

    try:
        worker.start()
    except RuntimeError:  # pragma: no cover - defensive fallback
        with _session_cleanup_lock:
            if _session_cleanup_worker is worker:
                _session_cleanup_worker = None
                _session_cleanup_pending = False
        _maybe_cleanup_inactive_sessions(now=current_time)
