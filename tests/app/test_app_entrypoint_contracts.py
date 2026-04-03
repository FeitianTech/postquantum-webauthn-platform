"""Contract tests for server application entrypoint behavior."""

from __future__ import annotations

import types

import pytest


def test_discover_project_root_falls_back_to_grandparent(tmp_path):
    app_module = pytest.importorskip("server.app.app")

    package_root = tmp_path / "one" / "two" / "three"
    package_root.mkdir(parents=True)

    discovered = app_module._discover_project_root(package_root)

    assert discovered == package_root.parents[1]


def test_main_bootstraps_metadata_and_starts_tls_server(monkeypatch):
    app_module = pytest.importorskip("server.app.app")

    calls = {}

    def _bootstrap(**kwargs):
        calls["bootstrap"] = kwargs

    def _run(**kwargs):
        calls["run"] = kwargs

    monkeypatch.setattr(
        app_module,
        "general",
        types.SimpleNamespace(ensure_metadata_bootstrapped=_bootstrap),
        raising=False,
    )
    monkeypatch.setattr(
        app_module,
        "app",
        types.SimpleNamespace(run=_run),
        raising=False,
    )

    app_module.main()

    assert calls["bootstrap"] == {"skip_if_reloader_parent": False}
    assert calls["run"] == {
        "host": "demo.ftsafe.demo",
        "port": 5000,
        "ssl_context": ("demo.ftsafe.demo.pem", "demo.ftsafe.demo-key.pem"),
        "debug": True,
    }


def test_main_skips_bootstrap_when_hook_is_not_callable(monkeypatch):
    app_module = pytest.importorskip("server.app.app")

    runs = []

    monkeypatch.setattr(
        app_module,
        "general",
        types.SimpleNamespace(ensure_metadata_bootstrapped="not-callable"),
        raising=False,
    )
    monkeypatch.setattr(
        app_module,
        "app",
        types.SimpleNamespace(run=lambda **kwargs: runs.append(kwargs)),
        raising=False,
    )

    app_module.main()

    assert len(runs) == 1
    assert runs[0]["host"] == "demo.ftsafe.demo"
