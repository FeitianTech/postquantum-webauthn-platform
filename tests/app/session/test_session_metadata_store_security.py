import pytest

from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata as session_store


def test_normalise_local_session_id_accepts_clean_identifier():
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
    with pytest.raises(ValueError):
        session_store._normalise_local_session_id(raw_session_id)


def test_session_blob_requires_non_empty_metadata_filename():
    with pytest.raises(ValueError):
        session_store._session_blob("session-abc", "///")


def test_session_blob_builds_session_scoped_path():
    blob_name = session_store._session_blob("session-abc", "custom.json")
    assert blob_name.endswith("/custom.json")
    assert "session-abc" in blob_name
    assert "/metadata/" in blob_name


def test_validate_session_metadata_filename_accepts_safe_json_name():
    assert mds_uploads._validate_session_metadata_filename("entry.json") == "entry.json"


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
    with pytest.raises(ValueError):
        mds_uploads._validate_session_metadata_filename(filename)
