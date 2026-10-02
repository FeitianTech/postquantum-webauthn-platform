"""Tests for the non-blocking worker warm-up."""

from __future__ import annotations

import threading
import time

from server.app import startup
from server.app.mds import cache as mds_cache
from server.app.mds import provisioning as mds_provisioning
from server.app.storage import common as storage_common


def test_background_warmup_defaults_to_cloud_run_only(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_BACKGROUND_WARMUP", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert startup.background_warmup_enabled() is False

    monkeypatch.setenv("K_SERVICE", "pqcwebauthn")
    assert startup.background_warmup_enabled() is True

    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "0")
    assert startup.background_warmup_enabled() is False


def test_start_background_warmup_returns_immediately(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "1")
    finished = threading.Event()

    def _slow_warmup():
        time.sleep(0.2)
        finished.set()

    monkeypatch.setattr(startup, "_run_background_warmup", _slow_warmup)

    started = time.perf_counter()
    thread = startup.start_background_warmup()
    elapsed = time.perf_counter() - started

    assert thread is not None
    assert elapsed < 0.1
    thread.join(timeout=5)
    assert finished.is_set()


def test_start_background_warmup_disabled_does_nothing(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_BACKGROUND_WARMUP", "0")

    assert startup.start_background_warmup() is None


def test_run_background_warmup_survives_failures(monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: True)
    monkeypatch.setattr(
        startup.cloud,
        "_ensure_bucket",
        lambda: (_ for _ in ()).throw(RuntimeError("no bucket")),
    )
    monkeypatch.setattr(
        mds_cache,
        "load_cached_metadata_snapshot",
        lambda: (_ for _ in ()).throw(RuntimeError("no metadata")),
    )

    startup._run_background_warmup()


def test_the_warmup_derives_the_explorers_files_before_reading_the_metadata(monkeypatch):
    calls = []
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    monkeypatch.setattr(mds_provisioning, "ensure_snapshot_available", lambda: calls.append("provision"))
    monkeypatch.setattr(mds_cache, "load_explorer_files", lambda: calls.append("explorer files"))
    monkeypatch.setattr(mds_cache, "load_cached_metadata_snapshot", lambda: calls.append("metadata"))

    startup._run_background_warmup()

    assert calls == ["provision", "explorer files", "metadata"]
