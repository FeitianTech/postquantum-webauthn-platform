import pytest


def test_normalise_local_session_id_accepts_clean_identifier():
    session_store = pytest.importorskip("server.app.session_metadata_store")

    assert session_store._normalise_local_session_id("session-123") == "session-123"


@pytest.mark.parametrize(
    "raw_session_id",
    [
        "",
        "   ",
        ".hidden",
        "../escape",
        "nested/session",
    ],
)
def test_normalise_local_session_id_rejects_invalid_values(raw_session_id):
    session_store = pytest.importorskip("server.app.session_metadata_store")

    with pytest.raises(ValueError):
        session_store._normalise_local_session_id(raw_session_id)


def test_session_blob_requires_non_empty_metadata_filename():
    session_store = pytest.importorskip("server.app.session_metadata_store")

    with pytest.raises(ValueError):
        session_store._session_blob("session-abc", "///")


def test_session_blob_builds_session_scoped_path():
    session_store = pytest.importorskip("server.app.session_metadata_store")

    blob_name = session_store._session_blob("session-abc", "custom.json")
    assert blob_name.endswith("/custom.json")
    assert "session-abc" in blob_name
    assert "/metadata/" in blob_name


def test_validate_session_metadata_filename_accepts_safe_json_name():
    metadata_module = pytest.importorskip("server.app.metadata")

    assert metadata_module._validate_session_metadata_filename("entry.json") == "entry.json"


@pytest.mark.parametrize(
    "filename",
    [
        "",
        "   ",
        ".hidden.json",
        "nested/entry.json",
        "../entry.json",
        "entry.txt",
    ],
)
def test_validate_session_metadata_filename_rejects_unsafe_values(filename):
    metadata_module = pytest.importorskip("server.app.metadata")

    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename(filename)


def test_prune_session_removes_empty_session(monkeypatch):
    session_store = pytest.importorskip("server.app.session_metadata_store")

    calls = []
    monkeypatch.setattr(session_store, "session_is_empty", lambda _session_id: True, raising=False)
    monkeypatch.setattr(
        session_store,
        "delete_file",
        lambda session_id, name, *, missing_ok=True: calls.append(("delete_file", session_id, name, missing_ok)),
        raising=False,
    )
    monkeypatch.setattr(
        session_store,
        "delete_session",
        lambda session_id: calls.append(("delete_session", session_id)),
        raising=False,
    )

    session_store.prune_session("session-1")

    assert calls[0] == ("delete_file", "session-1", session_store._LAST_ACCESS_BLOB, True)
    assert calls[1] == ("delete_session", "session-1")


def test_prune_session_keeps_non_empty_session(monkeypatch):
    session_store = pytest.importorskip("server.app.session_metadata_store")

    calls = []
    monkeypatch.setattr(session_store, "session_is_empty", lambda _session_id: False, raising=False)
    monkeypatch.setattr(
        session_store,
        "delete_file",
        lambda *args, **kwargs: calls.append(("delete_file", args, kwargs)),
        raising=False,
    )
    monkeypatch.setattr(
        session_store,
        "delete_session",
        lambda *args, **kwargs: calls.append(("delete_session", args, kwargs)),
        raising=False,
    )

    session_store.prune_session("session-2")

    assert calls == []
