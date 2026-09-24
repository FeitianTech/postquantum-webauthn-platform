"""/api/credentials says when it failed, instead of answering as if nothing were stored.

A listing that could not be read used to come back as 200 with [] -- exactly
what "you have no credentials" looks like -- and a DELETE that could not delete
reported {"status": "OK"}. Now a failure is an error status with a message, a
partial delete is reported as partial, and a record that cannot be shown is
counted in the ``X-Unreadable-Credentials`` header.
"""
from __future__ import annotations

import os

import pytest

_SESSION = "session-failures"


@pytest.fixture
def session_id(monkeypatch, metadata_module):
    monkeypatch.setattr(metadata_module, "ensure_metadata_session_id", lambda: _SESSION)
    return _SESSION


class _BareCredential:
    credential_id = b"bare-credential"
    public_key = {1: 2, 3: -7}
    aaguid = bytes(16)


def test_a_store_that_fails_part_way_is_a_failure_not_a_shorter_list(client, monkeypatch, session_id, storage_module):
    def _iterate(session_id=None):
        yield "alice@example.com", [_BareCredential()]
        raise OSError("bucket unreachable")

    monkeypatch.setattr(storage_module, "iter_credentials", _iterate)

    response = client.get("/api/credentials")

    assert response.status_code == 500
    assert response.get_json() == {"error": "The stored credentials could not be read, so none are listed."}


def test_a_record_that_cannot_be_shown_is_counted(client, monkeypatch, session_id, storage_module):
    monkeypatch.setattr(
        storage_module,
        "iter_credentials",
        lambda session_id=None: iter([("alice@example.com", [object(), _BareCredential()])]),
    )

    response = client.get("/api/credentials")

    assert response.status_code == 200
    assert [entry["email"] for entry in response.get_json()] == ["alice@example.com"]
    assert response.headers["X-Unreadable-Credentials"] == "1"


def test_a_complete_listing_carries_no_unreadable_count(client, monkeypatch, session_id, storage_module):
    monkeypatch.setattr(
        storage_module, "iter_credentials", lambda session_id=None: iter([("alice@example.com", [_BareCredential()])])
    )

    response = client.get("/api/credentials")

    assert response.status_code == 200
    assert "X-Unreadable-Credentials" not in response.headers


def test_a_partial_delete_is_reported_as_partial(client, monkeypatch, session_id, storage_module):
    monkeypatch.setattr(
        storage_module, "list_credentials", lambda session_id=None: {"alice@example.com": [], "bob@example.com": []}
    )

    def _delkey(username, *, session_id=None):
        if username == "bob@example.com":
            raise PermissionError("read-only")

    monkeypatch.setattr(storage_module, "delkey", _delkey)

    response = client.delete("/api/credentials")

    assert response.status_code == 500
    assert response.get_json() == {
        "status": "partial",
        "removed": 1,
        "failed": ["bob@example.com"],
        "error": "The stored credentials of 1 of 2 users could not be deleted.",
    }


def test_a_complete_delete_is_ok(client, monkeypatch, session_id, storage_module):
    monkeypatch.setattr(storage_module, "list_credentials", lambda session_id=None: {"alice@example.com": []})
    monkeypatch.setattr(storage_module, "delkey", lambda username, *, session_id=None: None)

    response = client.delete("/api/credentials")

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK", "removed": 1}


@pytest.fixture
def local_store(monkeypatch, tmp_path, storage_module):
    root = tmp_path / "session-credentials"
    root.mkdir()
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path))
    monkeypatch.setattr(storage_module, "_using_gcs", lambda: False)
    return storage_module


def test_delkey_raises_when_a_file_it_should_delete_stays(monkeypatch, local_store):
    local_store.savekey("alice", [{"credential_data": "x"}], session_id=_SESSION)
    real_remove = os.remove

    def _remove(path):
        if os.path.exists(path):
            raise PermissionError(f"read-only: {path}")
        real_remove(path)

    monkeypatch.setattr(local_store.os, "remove", _remove)

    with pytest.raises(PermissionError):
        local_store.delkey("alice", session_id=_SESSION)


def test_delkey_of_a_name_with_nothing_stored_is_not_an_error(local_store):
    local_store.delkey("nobody", session_id=_SESSION)


def test_the_endpoint_reports_a_file_it_could_not_delete(client, monkeypatch, session_id, local_store):
    local_store.savekey("alice@example.com", [{"credential_data": "x"}], session_id=_SESSION)
    local_store.savekey("bob@example.com", [{"credential_data": "x"}], session_id=_SESSION)
    real_remove = os.remove

    def _remove(path):
        if "bob" in os.path.basename(path) and os.path.exists(path):
            raise PermissionError("read-only")
        real_remove(path)

    monkeypatch.setattr(local_store.os, "remove", _remove)

    response = client.delete("/api/credentials")

    assert response.status_code == 500
    assert response.get_json()["status"] == "partial"
    assert response.get_json()["failed"] == ["bob@example.com"]
    assert local_store.readkey("alice@example.com", session_id=_SESSION) == []
