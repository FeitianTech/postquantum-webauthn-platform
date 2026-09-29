"""Local-storage contract tests for server.app.storage.credentials."""

from __future__ import annotations

import os
import pickle

import pytest

from server.app.storage import record_format


@pytest.fixture
def storage_local(monkeypatch, tmp_path):
    storage = pytest.importorskip("server.app.storage.credentials")

    monkeypatch.setattr(storage, "basepath", str(tmp_path))
    monkeypatch.setattr(
        storage,
        "_LOCAL_CREDENTIAL_BASE",
        str(tmp_path / "session-credentials"),
    )
    # Computed at import from the real source tree; patching basepath does not move it.
    monkeypatch.setattr(storage, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage, "_using_gcs", lambda: False)

    os.makedirs(storage._LOCAL_CREDENTIAL_BASE, exist_ok=True)

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
        storage._legacy_credential_blob(None)
    with pytest.raises(ValueError):
        storage._legacy_credential_blob("   ")

    with pytest.raises(ValueError):
        storage._local_directory(None)
    with pytest.raises(ValueError):
        storage._local_directory("   ")

    with pytest.raises(ValueError):
        storage._legacy_local_filename("   ")
    with pytest.raises(ValueError):
        storage._legacy_local_filename(123)
    with pytest.raises(ValueError):
        storage._local_filename("", "session-a")
    with pytest.raises(ValueError):
        storage._local_filename(123, "session-a")


def test_resolve_session_id_uses_explicit_value_or_metadata_fallback(storage_local, monkeypatch):
    storage, _ = storage_local

    assert storage._resolve_session_id("  explicit-session  ") == "explicit-session"

    metadata_module = pytest.importorskip("server.app.webauthn.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "fallback-session",
    )

    assert storage._resolve_session_id("   ") == "fallback-session"
    assert storage._resolve_session_id(None) == "fallback-session"


def test_candidate_gcs_blob_names_deduplicates_duplicates(storage_local, monkeypatch):
    storage, _ = storage_local

    monkeypatch.setattr(storage, "_credential_blob", lambda *_args, **_kwargs: "same")
    monkeypatch.setattr(storage, "_legacy_credential_blob", lambda *_args, **_kwargs: "same")

    assert list(storage._candidate_gcs_blob_names("alice", "session-a")) == ["same"]


def test_local_save_read_and_delete_roundtrip(storage_local):
    storage, _ = storage_local

    payload = [{"credential_data": "demo"}]

    storage.savekey("alice", payload, session_id="session-a")
    assert storage.readkey("alice", session_id="session-a") == payload

    storage.delkey("alice", session_id="session-a")
    assert storage.readkey("alice", session_id="session-a") == []


def test_local_readkey_falls_back_to_legacy_file(storage_local):
    storage, _ = storage_local

    legacy_payload = [{"legacy": True}]
    legacy_path = storage._legacy_local_filename("alice")
    os.makedirs(os.path.dirname(legacy_path), exist_ok=True)
    with open(legacy_path, "wb") as handle:
        handle.write(pickle.dumps(legacy_payload))

    assert storage.readkey("alice", session_id="session-a") == legacy_payload


def test_the_session_scoped_legacy_store_is_read_from_the_test_directory(storage_local):
    # The legacy store once lived in server/app/session-credentials/. Reading it
    # from there would read, and delkey would remove, the checkout's own files.
    storage, tmp_path = storage_local
    legacy_base = str(tmp_path / "legacy")
    assert storage._LEGACY_LOCAL_CREDENTIAL_BASE == legacy_base

    path = storage._local_filename("alice", "session-a", create=True, base=legacy_base)
    with open(path, "wb") as handle:
        handle.write(record_format.encode_records([{"where": "legacy session store"}]))

    assert storage.readkey("alice", session_id="session-a") == [{"where": "legacy session store"}]
    storage.delkey("alice", session_id="session-a")
    assert not os.path.exists(path)


def test_local_readkey_returns_empty_for_non_list_or_corrupt_pickle(storage_local):
    storage, _ = storage_local

    path = storage._local_filename("alice", "session-a", create=True)

    with open(path, "wb") as handle:
        handle.write(pickle.dumps({"not": "a list"}))
    assert storage.readkey("alice", session_id="session-a") == []

    with open(path, "wb") as handle:
        handle.write(b"not-a-pickle")
    assert storage.readkey("alice", session_id="session-a") == []


def test_local_delkey_swallows_missing_files(storage_local):
    storage, _ = storage_local

    storage.delkey("missing", session_id="session-a")


def test_convert_bytes_and_public_key_material_helpers(storage_local):
    storage, _ = storage_local

    converted = storage.convert_bytes_for_json(
        {
            "raw": b"\x01\x02",
            "nested": [bytearray(b"\x03"), memoryview(b"\x04")],
        }
    )
    assert converted["raw"] == "AQI"
    assert converted["nested"] == ["Aw", "BA"]

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

