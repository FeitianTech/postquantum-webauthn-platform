"""``visitor_session``: the namespace a visitor's uploads and credentials are stored under.

Its id is in the signed Flask session, and in a signed recovery cookie that outlives
it; page views refresh its last-access marker at most once per throttle window, and
a sweep deletes namespaces idle longer than ``INACTIVE_AGE``.
"""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import itsdangerous
import pytest
from flask import session

from server.app import visitor_session
from server.app.storage import session_metadata
from tests.app import visitor_namespace
from tests.app.entry_app import entry_app


@pytest.fixture
def touches(monkeypatch):
    calls = []
    monkeypatch.setattr(visitor_session, "_touch_last_access", lambda sid: calls.append(sid))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    return calls


@pytest.fixture
def fast_cleanup_interval(monkeypatch, metadata_state):
    """A sweep at most once a second, from a fresh cleanup state."""

    monkeypatch.setattr(visitor_session, "CLEANUP_INTERVAL", timedelta(seconds=1))


# The last-access marker: page views must not write it on every request.


def test_touch_is_deduplicated_within_one_request(touches):
    with entry_app().test_request_context("/"):
        visitor_session.note_activity("session-a")
        visitor_session.note_activity("session-a")

    assert touches == ["session-a"]


def test_touch_is_throttled_across_requests_and_writes_nothing_to_the_session(touches, monkeypatch):
    clock = [1_000_000.0]
    monkeypatch.setattr(visitor_session.time, "time", lambda: clock[0])

    for elapsed in (0, 60, 1799, 1800, 1860):
        clock[0] = 1_000_000.0 + elapsed
        with entry_app().test_request_context("/"):
            visitor_session.note_activity("session-a")
            assert dict(session) == {}

    assert touches == ["session-a", "session-a"]


def test_throttle_window_is_configurable(touches, monkeypatch):
    monkeypatch.setattr(visitor_session, "TOUCH_THROTTLE_SECONDS", 0.0)

    with entry_app().test_request_context("/"):
        visitor_session.note_activity("session-a")
    with entry_app().test_request_context("/"):
        visitor_session.note_activity("session-a")

    assert touches == ["session-a", "session-a"]


def test_new_session_does_not_write_marker(touches):
    with entry_app().test_request_context("/"):
        identifier = visitor_session.ensure_id()
        assert identifier

    assert touches == []


def test_touch_outside_request_context_is_throttled_too(touches):
    visitor_session.note_activity("session-a")
    visitor_session.note_activity("session-a")

    assert touches == ["session-a"]


def test_only_the_namespaces_inside_the_window_are_remembered_past_the_limit(touches, monkeypatch):
    monkeypatch.setattr(visitor_session, "_TOUCHES_KEPT", 3)
    clock = [1_000_000.0]
    monkeypatch.setattr(visitor_session.time, "time", lambda: clock[0])
    visitor_session.note_activity("session-a")
    visitor_session.note_activity("session-b")
    clock[0] += 3600
    visitor_session.note_activity("session-c")

    visitor_session.note_activity("session-d")

    assert set(visitor_session.TOUCHES.last) == {"session-c", "session-d"}


def test_a_namespace_that_is_not_one_is_not_touched(touches):
    visitor_session.note_activity("../escape")

    assert touches == []


def test_a_marker_that_cannot_be_written_or_read_is_passed_over(monkeypatch):
    def _unavailable(*_args, **_kwargs):
        raise OSError("storage unavailable")

    monkeypatch.setattr(session_metadata, "touch_last_access", _unavailable)
    monkeypatch.setattr(session_metadata, "resolve_last_access", _unavailable)
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)

    visitor_session.note_activity("session-a")
    assert visitor_session._resolve_last_access("session-a") is None


def test_health_endpoint_sets_no_session_cookie():
    response = entry_app().test_client().get("/health")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "ok"
    assert "Set-Cookie" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"


# The namespace id: the signed cookie, else a new one when asked for.


def _namespace_cookies(response) -> list[str]:
    return [value for value in response.headers.getlist("Set-Cookie") if value.startswith(f"{visitor_session.COOKIE_NAME}=")]


def test_a_new_visitor_gets_a_signed_lax_cookie_once_secure_as_the_session_cookie(touches, monkeypatch):
    app = entry_app()
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", True)

    with app.test_request_context("/"):
        identifier = visitor_session.current_id(create=True)
        assert visitor_session.current_id(create=True) == identifier
        assert dict(session) == {}
        response = app.process_response(app.response_class("ok"))

    (cookie,) = _namespace_cookies(response)
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    # The namespace name is signed with the application secret rather than sent
    # verbatim, so a caller cannot rewrite it to somebody else's.
    value = cookie.split(";", 1)[0].split("=", 1)[1]
    assert itsdangerous.URLSafeTimedSerializer(app.secret_key, salt=visitor_session.COOKIE_SALT).loads(value) == identifier


def test_only_a_cookie_this_server_signed_names_a_namespace(touches):
    app = entry_app()

    # An unsigned cookie naming a namespace is ignored: trusting it verbatim was an
    # IDOR, since any caller could name another visitor's namespace.
    with app.test_request_context("/", headers={"Cookie": f"{visitor_session.COOKIE_NAME}=cookie-session"}):
        assert visitor_session.current_id() is None

    with app.test_request_context("/", headers=visitor_namespace.header(app, "cookie-session")):
        assert visitor_session.current_id() == "cookie-session"


def test_the_cookie_is_signed_again_once_it_is_a_day_old(touches, monkeypatch):
    app = entry_app()
    cookie = visitor_namespace.header(app, "cookie-session")
    signed = time.time()

    for age, set_again in ((60.0, False), (visitor_session.COOKIE_REFRESH_SECONDS + 60.0, True)):
        monkeypatch.setattr(visitor_session.time, "time", lambda age=age: signed + age)
        with app.test_request_context("/", headers=cookie):
            assert visitor_session.current_id() == "cookie-session"
            response = app.process_response(app.response_class("ok"))
        assert bool(_namespace_cookies(response)) is set_again


def test_a_visitor_without_a_namespace_gets_one_only_when_asked_and_keeps_it_for_the_request(touches):
    with entry_app().test_request_context("/"):
        assert visitor_session.current_id() is None

        identifier = visitor_session.ensure_id()

        assert visitor_session.current_id() == identifier
        assert visitor_session.ensure_id() == identifier
        assert dict(session) == {}


def test_outside_a_request_there_is_no_namespace():
    assert visitor_session.current_id(create=True) is None
    with pytest.raises(RuntimeError, match="Unable to establish metadata session identifier"):
        visitor_session.ensure_id()


# The sweep of inactive namespaces.


def test_schedule_inactive_session_cleanup_runs_inline_when_async_disabled(fast_cleanup_interval, monkeypatch):
    observed_now = []

    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(visitor_session, "CLEANUP_ASYNC", False)
    monkeypatch.setattr(visitor_session, "_maybe_cleanup", lambda now=None: observed_now.append(now))

    visitor_session.schedule_cleanup()

    assert observed_now == [100.0]
    assert visitor_session.CLEANUP.worker is None
    assert visitor_session.CLEANUP.pending is False


def test_schedule_inactive_session_cleanup_marks_pending_when_worker_alive(fast_cleanup_interval, monkeypatch):
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
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inline cleanup should not run when worker is alive")),
    )

    visitor_session.schedule_cleanup()

    assert visitor_session.CLEANUP.worker is alive_worker
    assert visitor_session.CLEANUP.pending is True


def test_schedule_inactive_session_cleanup_falls_back_inline_when_thread_start_fails(fast_cleanup_interval, monkeypatch):
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
    monkeypatch.setattr(visitor_session, "_maybe_cleanup", lambda now=None: observed_now.append(now))

    visitor_session.schedule_cleanup()

    assert observed_now == [250.0]
    assert visitor_session.CLEANUP.worker is None
    assert visitor_session.CLEANUP.pending is False


def test_run_inactive_session_cleanup_worker_drains_pending_before_teardown(fast_cleanup_interval, monkeypatch):
    runs = []

    monkeypatch.setattr(visitor_session.CLEANUP, "worker", object())
    monkeypatch.setattr(visitor_session.CLEANUP, "pending", True)
    monkeypatch.setattr(visitor_session, "_maybe_cleanup", lambda: runs.append("cleanup"))

    visitor_session._run_cleanup_worker()

    assert runs == ["cleanup", "cleanup"]
    assert visitor_session.CLEANUP.pending is False
    assert visitor_session.CLEANUP.worker is None


def test_maybe_cleanup_inactive_sessions_deletes_only_stale_and_continues_on_delete_errors(fast_cleanup_interval, monkeypatch):
    now = 2_000_000.0
    monkeypatch.setattr(visitor_session.CLEANUP, "last_run", 0.0)
    monkeypatch.setattr(session_metadata, "list_sessions", lambda: ["stale-error", "stale-ok", "fresh", "unknown"])
    last_access = {"stale-error": 100.0, "stale-ok": 120.0, "fresh": now - 10.0, "unknown": None}
    monkeypatch.setattr(visitor_session, "_resolve_last_access", lambda session_id: last_access[session_id])

    delete_attempts = []

    def _delete_session(session_id):
        delete_attempts.append(session_id)
        if session_id == "stale-error":
            raise RuntimeError("cannot delete")

    monkeypatch.setattr(session_metadata, "delete_session", _delete_session)
    warnings = []
    monkeypatch.setattr(visitor_session.logger, "warning", lambda *args, **kwargs: warnings.append((args, kwargs)))

    visitor_session._maybe_cleanup(now=now)

    assert delete_attempts == ["stale-error", "stale-ok"]
    assert visitor_session.CLEANUP.last_run == now
    assert any("Failed to remove inactive metadata session" in str(call[0][0]) for call in warnings)


def test_a_sweep_that_cannot_list_the_namespaces_deletes_nothing(fast_cleanup_interval, monkeypatch):
    def _unavailable():
        raise OSError("storage unavailable")

    monkeypatch.setattr(session_metadata, "list_sessions", _unavailable)
    monkeypatch.setattr(session_metadata, "delete_session", lambda _sid: pytest.fail("nothing to delete"))

    visitor_session._maybe_cleanup(now=2_000_000.0)

    assert visitor_session.CLEANUP.last_run == 2_000_000.0
