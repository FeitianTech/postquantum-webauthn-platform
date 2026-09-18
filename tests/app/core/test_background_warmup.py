"""Tests for the non-blocking worker warm-up."""

from __future__ import annotations

import threading
import time

import pytest


@pytest.fixture
def startup_module():
    return pytest.importorskip("server.app.startup")


def test_background_warmup_defaults_to_cloud_run_only(startup_module, monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_BACKGROUND_WARMUP", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert startup_module.background_warmup_enabled() is False

    monkeypatch.setenv("K_SERVICE", "pqcwebauthn")
    assert startup_module.background_warmup_enabled() is True

    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "0")
    assert startup_module.background_warmup_enabled() is False


def test_start_background_warmup_returns_immediately(startup_module, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "1")
    finished = threading.Event()

    def _slow_warmup():
        time.sleep(0.2)
        finished.set()

    monkeypatch.setattr(startup_module, "_run_background_warmup", _slow_warmup)

    started = time.perf_counter()
    thread = startup_module.start_background_warmup()
    elapsed = time.perf_counter() - started

    assert thread is not None
    assert elapsed < 0.1
    thread.join(timeout=5)
    assert finished.is_set()


def test_start_background_warmup_disabled_does_nothing(startup_module, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "0")

    assert startup_module.start_background_warmup() is None


def test_run_background_warmup_survives_failures(startup_module, monkeypatch):
    monkeypatch.setattr(startup_module, "_should_warm_cloud_storage_configured", lambda: True)
    monkeypatch.setattr(
        startup_module.cloud,
        "_ensure_bucket",
        lambda: (_ for _ in ()).throw(RuntimeError("no bucket")),
    )
    metadata = pytest.importorskip("server.app.metadata")
    monkeypatch.setattr(
        metadata,
        "load_cached_metadata_snapshot",
        lambda: (_ for _ in ()).throw(RuntimeError("no metadata")),
    )

    startup_module._run_background_warmup()
