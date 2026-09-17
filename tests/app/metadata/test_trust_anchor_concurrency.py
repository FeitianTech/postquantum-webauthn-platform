"""Concurrency contracts for MDS trust status and base metadata caches."""

from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest
from flask import g

from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry


@pytest.fixture
def metadata_module(monkeypatch, metadata_runtime_state):
    module = pytest.importorskip("server.app.metadata")

    monkeypatch.setattr(metadata_runtime_state, "_base_metadata_trust_verified", True)

    return module


def _entry(module, aaguid: str):
    return MetadataBlobPayloadEntry.from_dict(
        {
            "aaguid": aaguid,
            "statusReports": [],
            "timeOfLastStatusChange": "2026-01-01",
            "metadataStatement": {
                "description": "Demo",
                "authenticatorVersion": 1,
                "schema": 3,
                "upv": [],
                "attestationTypes": [],
                "userVerificationDetails": [],
                "keyProtection": [],
                "matcherProtection": [],
                "attachmentHint": [],
                "tcDisplay": [],
                "attestationRootCertificates": [],
            },
        }
    )


def test_unknown_entry_is_never_reported_as_trusted(metadata_module):
    entry = _entry(metadata_module, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert metadata_module.metadata_entry_trust_anchor_status(entry) is None


def test_base_entry_reports_base_trust(metadata_module, metadata_runtime_state):
    entry = _entry(metadata_module, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    metadata_runtime_state._base_metadata_entry_ids = {id(entry)}

    assert metadata_module.metadata_entry_trust_anchor_status(entry) is True


def test_session_entries_stay_untrusted_while_other_sessions_run(metadata_module, monkeypatch, metadata_runtime_state, items_runtime, snapshot_runtime, app_config):
    base_entry = _entry(metadata_module, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    custom_entry = _entry(metadata_module, "cccccccc-cccc-cccc-cccc-cccccccccccc")
    base_metadata = MetadataBlobPayload(
        legal_header="",
        no=1,
        next_update=None,
        entries=(base_entry,),
    )
    metadata_runtime_state._base_metadata_entry_ids = {id(base_entry)}

    monkeypatch.setattr(
        snapshot_runtime, "_load_base_metadata", lambda: (base_metadata, 1.0)
    )
    monkeypatch.setattr(
        items_runtime,
        "list_session_metadata_items",
        lambda: (
            [SimpleNamespace(entry=custom_entry, legal_header="")]
            if getattr(g, "_test_has_custom_metadata", False)
            else []
        ),
        raising=False,
    )

    app = app_config.app
    iterations = 200
    barrier = threading.Barrier(2)
    observed = []
    failures = []

    def _custom_session():
        try:
            for _ in range(iterations):
                with app.test_request_context("/"):
                    g._test_has_custom_metadata = True
                    metadata_module.get_mds_verifier()
                    barrier.wait(timeout=5)
                    observed.append(
                        metadata_module.metadata_entry_trust_anchor_status(custom_entry)
                    )
        except Exception as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    def _base_session():
        try:
            for _ in range(iterations):
                with app.test_request_context("/"):
                    metadata_module.get_mds_verifier()
                    barrier.wait(timeout=5)
                    observed.append(
                        ("base", metadata_module.metadata_entry_trust_anchor_status(base_entry))
                    )
        except Exception as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    threads = [threading.Thread(target=_custom_session), threading.Thread(target=_base_session)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not failures
    custom_results = [value for value in observed if not isinstance(value, tuple)]
    base_results = [value for kind, value in (v for v in observed if isinstance(v, tuple))]
    assert custom_results == [False] * iterations
    assert base_results == [True] * iterations


def test_concurrent_cold_loads_parse_base_metadata_once(metadata_module, monkeypatch, tmp_path, snapshot_runtime):
    calls = []

    # The real snapshot is generated, not tracked, so this stands in for it.
    verified_path = tmp_path / "fido-mds3.verified.json"
    verified_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        snapshot_runtime, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False
    )
    verified_mtime = os.path.getmtime(verified_path)

    def _slow_fallback():
        calls.append(1)
        time.sleep(0.05)
        return SimpleNamespace(entries=()), verified_mtime

    monkeypatch.setattr(
        snapshot_runtime, "_load_verified_metadata_fallback", _slow_fallback, raising=False
    )

    threads = [
        threading.Thread(target=metadata_module._load_base_metadata) for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1


def test_concurrent_cleanup_checks_run_cleanup_once(metadata_module, monkeypatch, metadata_runtime_state, session_store):
    calls = []

    def _slow_list_sessions():
        calls.append(1)
        time.sleep(0.05)
        return []

    monkeypatch.setattr(metadata_runtime_state, "_session_metadata_last_cleanup", 0.0)
    monkeypatch.setattr(
        session_store, "list_sessions", _slow_list_sessions
    )

    now = time.time()
    threads = [
        threading.Thread(
            target=metadata_module._maybe_cleanup_inactive_sessions, kwargs={"now": now}
        )
        for _ in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1
