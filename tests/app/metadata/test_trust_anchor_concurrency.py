"""Concurrency contracts for MDS trust status and base metadata caches."""

from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest
from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry
from flask import g

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import verifier as mds_verifier
from server.app.webauthn import metadata as module
from tests.app.entry_app import entry_app


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    monkeypatch.setattr(mds_cache.CACHE, "trust_verified", True)

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

    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is None


def test_base_entry_reports_base_trust(metadata_module, metadata_state):
    entry = _entry(metadata_module, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    mds_cache.CACHE.entry_ids = {id(entry)}

    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is True


def test_session_entries_stay_untrusted_while_other_sessions_run(metadata_module, monkeypatch, metadata_state, sessions, blob, app_config):
    base_entry = _entry(metadata_module, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    custom_entry = _entry(metadata_module, "cccccccc-cccc-cccc-cccc-cccccccccccc")
    base_metadata = MetadataBlobPayload(
        legal_header="",
        no=1,
        next_update=None,
        entries=(base_entry,),
    )
    mds_cache.CACHE.entry_ids = {id(base_entry)}

    monkeypatch.setattr(
        blob, "_load_base_metadata", lambda: (base_metadata, 1.0)
    )
    monkeypatch.setattr(
        sessions,
        "list_session_metadata_items",
        lambda: (
            [SimpleNamespace(entry=custom_entry, legal_header="")]
            if getattr(g, "_test_has_custom_metadata", False)
            else []
        ),
    )

    app = entry_app()
    iterations = 200
    barrier = threading.Barrier(2)
    observed = []
    failures = []

    def _custom_session():
        try:
            for _ in range(iterations):
                with app.test_request_context("/"):
                    g._test_has_custom_metadata = True
                    mds_verifier.get_mds_verifier()
                    barrier.wait(timeout=5)
                    observed.append(
                        mds_verifier.metadata_entry_trust_anchor_status(custom_entry)
                    )
        except Exception as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    def _base_session():
        try:
            for _ in range(iterations):
                with app.test_request_context("/"):
                    mds_verifier.get_mds_verifier()
                    barrier.wait(timeout=5)
                    observed.append(
                        ("base", mds_verifier.metadata_entry_trust_anchor_status(base_entry))
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


def test_concurrent_cold_loads_parse_base_metadata_once(metadata_module, monkeypatch, tmp_path, blob):
    calls = []

    # The real snapshot is generated, not tracked, so this stands in for it.
    verified_path = tmp_path / "fido-mds3.verified.json"
    verified_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    verified_mtime = os.path.getmtime(verified_path)

    def _slow_fallback():
        calls.append(1)
        time.sleep(0.05)
        return SimpleNamespace(entries=()), verified_mtime

    monkeypatch.setattr(
        blob, "_load_verified_metadata_fallback", _slow_fallback
    )

    threads = [
        threading.Thread(target=blob._load_base_metadata) for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1


def test_concurrent_cleanup_checks_run_cleanup_once(metadata_module, monkeypatch, metadata_state, session_store):
    calls = []

    def _slow_list_sessions():
        calls.append(1)
        time.sleep(0.05)
        return []

    monkeypatch.setattr(visitor_session.CLEANUP, "last_run", 0.0)
    monkeypatch.setattr(
        session_store, "list_sessions", _slow_list_sessions
    )

    now = time.time()
    threads = [
        threading.Thread(
            target=visitor_session._maybe_cleanup, kwargs={"now": now}
        )
        for _ in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1
