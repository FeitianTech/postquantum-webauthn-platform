"""On GCS, sessions are listed as the folders under the user folder, not as every object.

``list_sessions`` (whose caller is the inactive-session cleanup) used to list
every object of every session -- credentials, artifacts, metadata -- to find
the session folders, and took a flat legacy credential copy beside them for a
session named after the file.
"""
from __future__ import annotations

import pytest

from server.app.storage import session_metadata
from server.app.webauthn.metadata import sessions
from server.app.webauthn.metadata import state as metadata_state

from ..storage import fake_gcs

SESSIONS = ("s1", "s2", "s3")


@pytest.fixture
def bucket(monkeypatch):
    bucket = fake_gcs.install(monkeypatch, session_metadata)
    for session in SESSIONS:
        bucket.put(f"user-data/{session}/credentials/user_credential_data.json", b"{}")
        bucket.put(f"user-data/{session}/credential-artifacts/0123abcd.json", b"{}")
        bucket.put(f"user-data/{session}/metadata/metadata.json", b"{}")
        bucket.put(f"user-data/{session}/.last-access", b"")
    bucket.put("user-data/legacy-user_credential_data.json", b"{}")
    return bucket


def test_sessions_are_listed_as_folders(bucket):
    assert session_metadata.list_sessions() == list(SESSIONS)
    assert bucket.list_calls == [("user-data/", "/")]


def test_the_inactive_session_cleanup_still_sees_every_session(bucket, monkeypatch):
    removed = []
    monkeypatch.setattr(session_metadata, "resolve_last_access", lambda _session: 0.0)
    monkeypatch.setattr(session_metadata, "delete_session", removed.append)
    monkeypatch.setattr(metadata_state, "_session_metadata_last_cleanup", 0.0)

    sessions._maybe_cleanup_inactive_sessions(now=10.0 ** 9)

    assert removed == list(SESSIONS)
