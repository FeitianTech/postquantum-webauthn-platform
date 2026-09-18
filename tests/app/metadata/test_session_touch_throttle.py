"""Page views must not write the session last-access marker on every request."""

from __future__ import annotations

import time

import pytest
from flask import session


@pytest.fixture
def touch_env(monkeypatch, app_config, sessions):
    metadata = pytest.importorskip("server.app.metadata")
    cleanup = pytest.importorskip("server.app.metadata.sessions")

    calls = []
    monkeypatch.setattr(cleanup, "_touch_session_last_access", lambda sid: calls.append(sid))
    monkeypatch.setattr(cleanup, "_schedule_inactive_session_cleanup", lambda: None)
    monkeypatch.delenv(metadata._SESSION_METADATA_TOUCH_THROTTLE_ENV, raising=False)
    return metadata, app_config.app, calls


def test_touch_is_deduplicated_within_one_request(touch_env):
    metadata, app, calls = touch_env

    with app.test_request_context("/"):
        metadata._note_session_activity("session-a")
        metadata._note_session_activity("session-a")
        assert isinstance(session[metadata._SESSION_METADATA_TOUCH_KEY], float)

    assert calls == ["session-a"]


def test_touch_is_throttled_across_requests(touch_env):
    metadata, app, calls = touch_env
    key = metadata._SESSION_METADATA_TOUCH_KEY

    with app.test_request_context("/"):
        session[key] = time.time() - 60
        metadata._note_session_activity("session-a")
    assert calls == []

    with app.test_request_context("/"):
        session[key] = time.time() - 3600
        metadata._note_session_activity("session-a")
    assert calls == ["session-a"]


def test_throttle_window_is_configurable(touch_env, monkeypatch, app_config):
    metadata, app, calls = touch_env
    monkeypatch.setenv(metadata._SESSION_METADATA_TOUCH_THROTTLE_ENV, "30")

    with app.test_request_context("/"):
        session[metadata._SESSION_METADATA_TOUCH_KEY] = time.time() - 60
        metadata._note_session_activity("session-a")

    assert calls == ["session-a"]


def test_new_session_does_not_write_marker(touch_env):
    metadata, app, calls = touch_env

    with app.test_request_context("/"):
        identifier = metadata.ensure_metadata_session_id()
        assert identifier
        assert metadata._SESSION_METADATA_TOUCH_KEY in session

    assert calls == []


def test_touch_outside_request_context_is_unthrottled(touch_env):
    metadata, _app, calls = touch_env

    metadata._note_session_activity("session-a")
    metadata._note_session_activity("session-a")

    assert calls == ["session-a", "session-a"]


def test_health_endpoint_sets_no_session_cookie(app_config):
    pytest.importorskip("server.app.app")

    response = app_config.app.test_client().get("/health")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "ok"
    assert "Set-Cookie" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
