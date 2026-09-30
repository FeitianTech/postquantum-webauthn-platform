"""Page views must not write the session last-access marker on every request."""

from __future__ import annotations

import time

import pytest
from flask import session

from server.app import visitor_session
from server.app.webauthn import metadata
from tests.app.entry_app import entry_app


@pytest.fixture
def touch_env(monkeypatch, app_config, sessions):
    calls = []
    monkeypatch.setattr(visitor_session, "_touch_last_access", lambda sid: calls.append(sid))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    return metadata, entry_app(), calls


def test_touch_is_deduplicated_within_one_request(touch_env):
    metadata, app, calls = touch_env

    with app.test_request_context("/"):
        visitor_session.note_activity("session-a")
        visitor_session.note_activity("session-a")
        assert isinstance(session[visitor_session.TOUCH_KEY], float)

    assert calls == ["session-a"]


def test_touch_is_throttled_across_requests(touch_env):
    metadata, app, calls = touch_env
    key = visitor_session.TOUCH_KEY

    with app.test_request_context("/"):
        session[key] = time.time() - 60
        visitor_session.note_activity("session-a")
    assert calls == []

    with app.test_request_context("/"):
        session[key] = time.time() - 3600
        visitor_session.note_activity("session-a")
    assert calls == ["session-a"]


def test_throttle_window_is_configurable(touch_env, monkeypatch, app_config):
    metadata, app, calls = touch_env
    monkeypatch.setattr(visitor_session, "TOUCH_THROTTLE_SECONDS", 30.0)

    with app.test_request_context("/"):
        session[visitor_session.TOUCH_KEY] = time.time() - 60
        visitor_session.note_activity("session-a")

    assert calls == ["session-a"]


def test_new_session_does_not_write_marker(touch_env):
    metadata, app, calls = touch_env

    with app.test_request_context("/"):
        identifier = visitor_session.ensure_id()
        assert identifier
        assert visitor_session.TOUCH_KEY in session

    assert calls == []


def test_touch_outside_request_context_is_unthrottled(touch_env):
    metadata, _app, calls = touch_env

    visitor_session.note_activity("session-a")
    visitor_session.note_activity("session-a")

    assert calls == ["session-a", "session-a"]


def test_health_endpoint_sets_no_session_cookie(app_config):
    response = entry_app().test_client().get("/health")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "ok"
    assert "Set-Cookie" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
