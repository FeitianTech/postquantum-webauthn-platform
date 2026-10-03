"""Concurrency contracts for MDS trust status and base metadata caches."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from fido2.mds3 import MetadataBlobPayloadEntry
from fido2.webauthn import Aaguid
from flask import g

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import uploads as mds_uploads
from server.app.mds import verifier as mds_verifier
from server.app.storage import session_metadata
from tests.app.entry_app import entry_app


def _raw(aaguid: str) -> dict:
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": "Demo",
            "aaguid": aaguid,
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


def test_unknown_entry_is_never_reported_as_trusted(metadata_state):
    entry = MetadataBlobPayloadEntry.from_dict(_raw("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))

    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is None


def test_session_entries_stay_untrusted_while_other_sessions_run(monkeypatch, metadata_state):
    packaged = [_raw("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    custom_entry = MetadataBlobPayloadEntry.from_dict(_raw("cccccccc-cccc-cccc-cccc-cccccccccccc"))
    monkeypatch.setattr(mds_cache, "load_verified_entries", lambda: packaged)
    monkeypatch.setattr(
        mds_uploads,
        "list_session_metadata_items",
        lambda: (
            [SimpleNamespace(entry=custom_entry, legal_header="")]
            if getattr(g, "_test_has_custom_metadata", False)
            else []
        ),
    )

    app = entry_app()
    with app.test_request_context("/"):
        base_entry = mds_verifier.get_mds_verifier().find_entry_by_aaguid(Aaguid.parse(packaged[0]["aaguid"]))
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


def test_concurrent_cold_loads_read_the_verified_entries_once(metadata_state, monkeypatch, tmp_path):
    calls = []

    # The real snapshot is generated, not tracked, so this stands in for it.
    verified_path = tmp_path / "fido-mds3.verified.json"
    verified_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))

    def _slow_payload():
        calls.append(1)
        time.sleep(0.05)
        return {"entries": []}

    monkeypatch.setattr(mds_cache, "_load_verified_metadata_payload", _slow_payload)

    threads = [threading.Thread(target=mds_cache.load_verified_entries) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1


def test_concurrent_cleanup_checks_run_cleanup_once(monkeypatch, metadata_state):
    calls = []

    def _slow_list_sessions():
        calls.append(1)
        time.sleep(0.05)
        return []

    monkeypatch.setattr(visitor_session.CLEANUP, "last_run", 0.0)
    monkeypatch.setattr(
        session_metadata, "list_sessions", _slow_list_sessions
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
