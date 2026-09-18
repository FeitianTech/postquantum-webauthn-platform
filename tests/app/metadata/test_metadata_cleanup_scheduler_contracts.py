import threading
import time
from datetime import timedelta

import pytest


@pytest.fixture
def sessions(monkeypatch):
    module = pytest.importorskip("server.app.webauthn.metadata.sessions")
    monkeypatch.setattr(module, "_SESSION_METADATA_CLEANUP_INTERVAL", timedelta(seconds=1))
    return module


@pytest.fixture
def metadata_module(monkeypatch, metadata_state, sessions):
    return pytest.importorskip("server.app.webauthn.metadata")


def test_schedule_inactive_session_cleanup_runs_inline_when_async_disabled(metadata_module, monkeypatch, metadata_state, sessions):
    observed_now = []

    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(sessions, "_cleanup_async_enabled", lambda: False)
    monkeypatch.setattr(
        sessions,
        "_maybe_cleanup_inactive_sessions",
        lambda now=None: observed_now.append(now),
    )

    metadata_module._schedule_inactive_session_cleanup()

    assert observed_now == [100.0]
    assert metadata_state._session_cleanup_worker is None
    assert metadata_state._session_cleanup_pending is False


def test_schedule_inactive_session_cleanup_marks_pending_when_worker_alive(metadata_module, monkeypatch, metadata_state, sessions):
    class _AliveWorker:
        def is_alive(self):
            return True

    alive_worker = _AliveWorker()

    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(sessions, "_cleanup_async_enabled", lambda: True)
    monkeypatch.setattr(metadata_state, "_session_cleanup_worker", alive_worker)
    monkeypatch.setattr(
        sessions,
        "_maybe_cleanup_inactive_sessions",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("inline cleanup should not run when worker is alive")
        ),
    )

    metadata_module._schedule_inactive_session_cleanup()

    assert metadata_state._session_cleanup_worker is alive_worker
    assert metadata_state._session_cleanup_pending is True


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
    monkeypatch.setattr(sessions, "_cleanup_async_enabled", lambda: True)
    monkeypatch.setattr(threading, "Thread", _FailingThread, raising=False)
    monkeypatch.setattr(
        sessions,
        "_maybe_cleanup_inactive_sessions",
        lambda now=None: observed_now.append(now),
    )

    metadata_module._schedule_inactive_session_cleanup()

    assert observed_now == [250.0]
    assert metadata_state._session_cleanup_worker is None
    assert metadata_state._session_cleanup_pending is False


def test_run_inactive_session_cleanup_worker_drains_pending_before_teardown(metadata_module, monkeypatch, metadata_state, sessions):
    runs = []

    monkeypatch.setattr(metadata_state, "_session_cleanup_worker", object())
    monkeypatch.setattr(metadata_state, "_session_cleanup_pending", True)
    monkeypatch.setattr(
        sessions,
        "_maybe_cleanup_inactive_sessions",
        lambda: runs.append("cleanup"),
    )

    metadata_module._run_inactive_session_cleanup_worker()

    assert runs == ["cleanup", "cleanup"]
    assert metadata_state._session_cleanup_pending is False
    assert metadata_state._session_cleanup_worker is None


def test_maybe_cleanup_inactive_sessions_deletes_only_stale_and_continues_on_delete_errors(metadata_module, monkeypatch, metadata_state, sessions, session_store, app_config):
    now = 2_000_000.0

    monkeypatch.setattr(metadata_state, "_session_metadata_last_cleanup", 0.0)
    monkeypatch.setattr(
        sessions,
        "_SESSION_METADATA_CLEANUP_INTERVAL",
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
        sessions,
        "_resolve_session_last_access",
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
        raising=False,
    )

    warnings = []
    monkeypatch.setattr(
        app_config.app.logger,
        "warning",
        lambda *args, **kwargs: warnings.append((args, kwargs)),
        raising=False,
    )

    metadata_module._maybe_cleanup_inactive_sessions(now=now)

    assert delete_attempts == ["stale-error", "stale-ok"]
    assert metadata_state._session_metadata_last_cleanup == now
    assert any("Failed to remove inactive metadata session" in str(call[0][0]) for call in warnings)
