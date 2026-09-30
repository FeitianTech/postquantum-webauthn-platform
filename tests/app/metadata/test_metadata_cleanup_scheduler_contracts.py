import importlib
import threading
import time
from datetime import timedelta

import pytest

from server.app import visitor_session
from server.app.mds import uploads as module


@pytest.fixture
def sessions(monkeypatch):
    monkeypatch.setattr(visitor_session, "CLEANUP_INTERVAL", timedelta(seconds=1))
    return module


@pytest.fixture
def metadata_module(monkeypatch, metadata_state, sessions):
    return importlib.import_module("server.app.webauthn.metadata")


def test_schedule_inactive_session_cleanup_runs_inline_when_async_disabled(metadata_module, monkeypatch, metadata_state, sessions):
    observed_now = []

    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(visitor_session, "CLEANUP_ASYNC", False)
    monkeypatch.setattr(
        visitor_session,
        "_maybe_cleanup",
        lambda now=None: observed_now.append(now),
    )

    visitor_session.schedule_cleanup()

    assert observed_now == [100.0]
    assert visitor_session.CLEANUP.worker is None
    assert visitor_session.CLEANUP.pending is False


def test_schedule_inactive_session_cleanup_marks_pending_when_worker_alive(metadata_module, monkeypatch, metadata_state, sessions):
    class _AliveWorker:
        def is_alive(self):
            return True

    alive_worker = _AliveWorker()

    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(visitor_session, "CLEANUP_ASYNC", True)
    monkeypatch.setattr(visitor_session.CLEANUP, "worker", alive_worker)
    monkeypatch.setattr(
        visitor_session,
        "_maybe_cleanup",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("inline cleanup should not run when worker is alive")
        ),
    )

    visitor_session.schedule_cleanup()

    assert visitor_session.CLEANUP.worker is alive_worker
    assert visitor_session.CLEANUP.pending is True


def test_schedule_inactive_session_cleanup_falls_back_inline_when_thread_start_fails(metadata_module, monkeypatch, metadata_state, sessions):
    observed_now = []

    class _FailingThread:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("thread start failed")

        def is_alive(self):
            return False

    monkeypatch.setattr(time, "time", lambda: 250.0)
    monkeypatch.setattr(visitor_session, "CLEANUP_ASYNC", True)
    monkeypatch.setattr(threading, "Thread", _FailingThread)
    monkeypatch.setattr(
        visitor_session,
        "_maybe_cleanup",
        lambda now=None: observed_now.append(now),
    )

    visitor_session.schedule_cleanup()

    assert observed_now == [250.0]
    assert visitor_session.CLEANUP.worker is None
    assert visitor_session.CLEANUP.pending is False


def test_run_inactive_session_cleanup_worker_drains_pending_before_teardown(metadata_module, monkeypatch, metadata_state, sessions):
    runs = []

    monkeypatch.setattr(visitor_session.CLEANUP, "worker", object())
    monkeypatch.setattr(visitor_session.CLEANUP, "pending", True)
    monkeypatch.setattr(
        visitor_session,
        "_maybe_cleanup",
        lambda: runs.append("cleanup"),
    )

    visitor_session._run_cleanup_worker()

    assert runs == ["cleanup", "cleanup"]
    assert visitor_session.CLEANUP.pending is False
    assert visitor_session.CLEANUP.worker is None


def test_maybe_cleanup_inactive_sessions_deletes_only_stale_and_continues_on_delete_errors(metadata_module, monkeypatch, metadata_state, sessions, session_store, app_config):
    now = 2_000_000.0

    monkeypatch.setattr(visitor_session.CLEANUP, "last_run", 0.0)
    monkeypatch.setattr(
        visitor_session,
        "CLEANUP_INTERVAL",
        timedelta(seconds=1),
    )

    monkeypatch.setattr(
        session_store,
        "list_sessions",
        lambda: ["stale-error", "stale-ok", "fresh", "unknown"],
    )

    last_access = {
        "stale-error": 100.0,
        "stale-ok": 120.0,
        "fresh": now - 10.0,
        "unknown": None,
    }
    monkeypatch.setattr(
        visitor_session,
        "_resolve_last_access",
        lambda session_id: last_access[session_id],
    )

    delete_attempts = []

    def _delete_session(session_id):
        delete_attempts.append(session_id)
        if session_id == "stale-error":
            raise RuntimeError("cannot delete")

    monkeypatch.setattr(
        session_store,
        "delete_session",
        _delete_session,
    )

    warnings = []
    monkeypatch.setattr(
        visitor_session.logger,
        "warning",
        lambda *args, **kwargs: warnings.append((args, kwargs)),
    )

    visitor_session._maybe_cleanup(now=now)

    assert delete_attempts == ["stale-error", "stale-ok"]
    assert visitor_session.CLEANUP.last_run == now
    assert any("Failed to remove inactive metadata session" in str(call[0][0]) for call in warnings)
