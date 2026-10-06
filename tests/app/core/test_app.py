"""Tests of app behavior."""

from __future__ import annotations

import types

from server.app import app as app_module


def test_main_starts_the_development_server(monkeypatch):
    calls = {}

    def _run(**kwargs):
        calls["run"] = kwargs

    monkeypatch.setattr(
        app_module,
        "app",
        types.SimpleNamespace(run=_run),
    )

    app_module.main()

    assert calls["run"] == {
        "host": "localhost",
        "port": 8000,
        "debug": True,
    }
