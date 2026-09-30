"""Local-storage contract tests for server.app.storage.credentials."""

from __future__ import annotations

import os
import pickle

import pytest

from server.app import visitor_session
from server.app.storage import common as storage_common
from server.app.storage import credentials as storage
from tests.app.storage.credential_seed import seed_records


@pytest.fixture
def storage_local(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "session-credentials"))
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)

    os.makedirs(storage._local_credential_base(), exist_ok=True)

    return storage, tmp_path


def test_storage_identifier_validators_reject_invalid_inputs(storage_local):
    storage, _ = storage_local

    with pytest.raises(ValueError):
        storage._credential_prefix(None)
    with pytest.raises(ValueError):
        storage._credential_prefix("   ")

    with pytest.raises(ValueError):
        storage._credential_blob(None, "session-a")
    with pytest.raises(ValueError):
        storage._credential_blob("", "session-a")


    with pytest.raises(ValueError):
        storage._local_filename("", "session-a")
    with pytest.raises(ValueError):
        storage._local_filename(123, "session-a")


def test_resolve_session_id_uses_explicit_value_or_metadata_fallback(storage_local, monkeypatch):
    storage, _ = storage_local

    assert storage._resolve_session_id("  explicit-session  ") == "explicit-session"

    monkeypatch.setattr(
        visitor_session,
        "ensure_id",
        lambda: "fallback-session",
    )

    assert storage._resolve_session_id("   ") == "fallback-session"
    assert storage._resolve_session_id(None) == "fallback-session"


def test_local_save_and_read_roundtrip(storage_local):
    storage, _ = storage_local

    payload = [{"credential_data": "demo"}]

    seed_records(storage, "alice", payload, session_id="session-a")
    assert storage.readkey("alice", session_id="session-a") == payload


def test_local_readkey_returns_empty_for_content_that_is_not_json(storage_local):
    storage, _ = storage_local

    path = storage._local_filename("alice", "session-a", create=True)

    with open(path, "wb") as handle:
        handle.write(pickle.dumps({"not": "a list"}))
    assert storage.readkey("alice", session_id="session-a") == []

    with open(path, "wb") as handle:
        handle.write(b"not-a-pickle")
    assert storage.readkey("alice", session_id="session-a") == []


def test_public_key_material_helper(storage_local):
    storage, _ = storage_local

    target = {}
    public_key = {1: "type-a", 3: -7, -1: b"\xAA\xBB"}
    storage.add_public_key_material(target, public_key)

    assert target["publicKeyCose"][-1] == "qrs"
    assert target["publicKeyBytes"] == "qrs"
    assert target["publicKeyType"] == "type-a"
    assert target["publicKeyAlgorithm"] == -7


def test_add_public_key_material_respects_existing_type_and_algorithm(storage_local):
    storage, _ = storage_local

    target = {"publicKeyType": "existing-type", "publicKeyAlgorithm": "existing-alg"}
    storage.add_public_key_material(target, {1: "new-type", 3: "new-alg"})

    assert target["publicKeyType"] == "existing-type"
    assert target["publicKeyAlgorithm"] == "existing-alg"

    untouched = {"x": 1}
    storage.add_public_key_material(untouched, "not-a-dict")
    assert untouched == {"x": 1}
