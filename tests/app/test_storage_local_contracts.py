"""Local-storage contract tests for server.app.storage."""

from __future__ import annotations

import os
import pickle

import pytest


@pytest.fixture
def storage_local(monkeypatch, tmp_path):
    storage = pytest.importorskip("server.app.storage")

    monkeypatch.setattr(storage, "basepath", str(tmp_path), raising=False)
    monkeypatch.setattr(
        storage,
        "_LOCAL_CREDENTIAL_BASE",
        str(tmp_path / "session-credentials"),
        raising=False,
    )
    monkeypatch.setattr(storage, "_using_gcs", lambda: False, raising=False)

    os.makedirs(storage._LOCAL_CREDENTIAL_BASE, exist_ok=True)

    return storage, tmp_path


def test_storage_identifier_validators_reject_invalid_inputs(storage_local):
    storage, _ = storage_local

    with pytest.raises(ValueError):
        storage._user_root_prefix(None)
    with pytest.raises(ValueError):
        storage._user_root_prefix("   ")

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

    metadata_module = pytest.importorskip("server.app.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "fallback-session",
        raising=False,
    )

    assert storage._resolve_session_id("   ") == "fallback-session"
    assert storage._resolve_session_id(None) == "fallback-session"


def test_candidate_gcs_blob_names_deduplicates_duplicates(storage_local, monkeypatch):
    storage, _ = storage_local

    monkeypatch.setattr(storage, "_credential_blob", lambda *_args, **_kwargs: "same")
    monkeypatch.setattr(storage, "_legacy_credential_blob", lambda *_args, **_kwargs: "same")

    assert list(storage._candidate_gcs_blob_names("alice", "session-a")) == ["same"]


def test_list_credential_blob_names_filters_duplicates_nested_and_invalid_entries(storage_local, monkeypatch):
    storage, _ = storage_local

    session_id = "session-a"
    primary_prefix = storage._build_search_prefix(storage._credential_prefix(session_id))
    legacy_prefix = storage._build_search_prefix(storage._USER_FOLDER_PREFIX)

    primary_blob = f"{primary_prefix}alice_credential_data.pkl"
    legacy_blob = f"{legacy_prefix}bob_credential_data.pkl"

    def _list(prefix: str):
        if prefix == primary_prefix:
            return iter(
                [
                    primary_blob,
                    f"{primary_prefix}invalid.txt",
                    f"{primary_prefix}_credential_data.pkl",
                ]
            )
        if prefix == legacy_prefix:
            return iter(
                [
                    primary_blob,  # duplicate user (already seen)
                    f"{legacy_prefix}nested/bob_credential_data.pkl",  # nested legacy path
                    legacy_blob,
                ]
            )
        return iter([])

    monkeypatch.setattr(storage, "list_blob_names", _list)

    assert list(storage._list_credential_blob_names(session_id)) == [
        ("alice", primary_blob),
        ("bob", legacy_blob),
    ]


def test_list_credential_blob_names_avoids_duplicate_search_prefixes(storage_local, monkeypatch):
    storage, _ = storage_local

    calls = []

    monkeypatch.setattr(storage, "_credential_prefix", lambda _sid: storage._USER_FOLDER_PREFIX)
    monkeypatch.setattr(storage, "list_blob_names", lambda prefix: calls.append(prefix) or iter([]))

    assert list(storage._list_credential_blob_names("session-a")) == []
    assert len(calls) == 1


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


def test_iter_credentials_reads_local_session_and_legacy_files(storage_local):
    storage, _ = storage_local

    session_dir = storage._local_directory("session-a", create=True)

    with open(os.path.join(session_dir, "alice_credential_data.pkl"), "wb") as handle:
        handle.write(pickle.dumps([{"where": "session"}]))
    with open(os.path.join(session_dir, "broken_credential_data.pkl"), "wb") as handle:
        handle.write(b"broken")
    with open(os.path.join(session_dir, "_credential_data.pkl"), "wb") as handle:
        handle.write(pickle.dumps([{"ignore": True}]))
    with open(os.path.join(session_dir, "note.txt"), "wb") as handle:
        handle.write(b"ignored")

    legacy_path = storage._legacy_local_filename("bob")
    with open(legacy_path, "wb") as handle:
        handle.write(pickle.dumps([{"where": "legacy"}]))

    results = dict(storage.iter_credentials(session_id="session-a"))

    assert results == {
        "alice": [{"where": "session"}],
        "bob": [{"where": "legacy"}],
    }


def test_iter_credentials_handles_missing_session_directory(storage_local):
    storage, _ = storage_local

    assert list(storage.iter_credentials(session_id="missing-session")) == []


def test_iter_credentials_skips_unreadable_empty_and_non_list_payloads(storage_local, monkeypatch):
    storage, _ = storage_local

    session_dir = storage._local_directory("session-a", create=True)

    unreadable_name = "unreadable_credential_data.pkl"
    empty_name = "empty_credential_data.pkl"
    badtype_name = "badtype_credential_data.pkl"

    with open(os.path.join(session_dir, unreadable_name), "wb") as handle:
        handle.write(pickle.dumps(["unused"]))
    with open(os.path.join(session_dir, empty_name), "wb") as handle:
        handle.write(b"")
    with open(os.path.join(session_dir, badtype_name), "wb") as handle:
        handle.write(pickle.dumps({"not": "a-list"}))

    with open(os.path.join(storage.basepath, "_credential_data.pkl"), "wb") as handle:
        handle.write(b"")

    legacy_bad_path = storage._legacy_local_filename("legacybad")
    with open(legacy_bad_path, "wb") as handle:
        handle.write(pickle.dumps(["unused"]))

    legacy_empty_path = storage._legacy_local_filename("legacyempty")
    with open(legacy_empty_path, "wb") as handle:
        handle.write(b"")

    real_open = open

    def _open(path, mode="r", *args, **kwargs):
        path_str = str(path)
        if path_str.endswith(unreadable_name) or path_str == legacy_bad_path:
            raise OSError("blocked")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _open)

    assert list(storage.iter_credentials(session_id="session-a")) == []


def test_list_credentials_returns_mapping_from_iterator(storage_local, monkeypatch):
    storage, _ = storage_local

    monkeypatch.setattr(
        storage,
        "iter_credentials",
        lambda **_kwargs: iter([("alice", [1]), ("bob", [2])]),
    )

    assert storage.list_credentials(session_id="session-a") == {
        "alice": [1],
        "bob": [2],
    }


def test_convert_bytes_and_public_key_material_helpers(storage_local):
    storage, _ = storage_local

    converted = storage.convert_bytes_for_json(
        {
            "raw": b"\x01\x02",
            "nested": [bytearray(b"\x03"), memoryview(b"\x04")],
        }
    )
    assert converted["raw"] == "AQI="
    assert converted["nested"] == ["Aw==", "BA=="]

    target = {}
    public_key = {1: "type-a", 3: -7, -1: b"\xAA\xBB"}
    storage.add_public_key_material(target, public_key)

    assert target["publicKeyCose"][-1] == "qrs="
    assert target["publicKeyBytes"] == "qrs="
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


def test_extract_credential_data_supports_dict_and_object(storage_local):
    storage, _ = storage_local

    assert storage.extract_credential_data({"credential_data": "value"}) == "value"

    obj = object()
    assert storage.extract_credential_data(obj) is obj
