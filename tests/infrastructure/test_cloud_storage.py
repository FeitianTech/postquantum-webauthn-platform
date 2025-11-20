"""Tests for the local storage helpers (GCS-compatible interface)."""

from __future__ import annotations

import os
import tempfile

import pytest

from server.server import cloud_storage


@pytest.fixture
def temp_storage(monkeypatch):
    """Create a temporary storage directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(cloud_storage, "_STORAGE_BASE_PATH", tmpdir)
        yield tmpdir


def test_gcs_enabled_always_returns_true():
    """Local storage is always enabled."""
    assert cloud_storage.gcs_enabled() is True


def test_ensure_ready_creates_directory(temp_storage):
    """ensure_ready should create the storage directory if it doesn't exist."""
    # Remove the directory to test creation
    os.rmdir(temp_storage)
    assert not os.path.exists(temp_storage)

    cloud_storage.ensure_ready()

    assert os.path.isdir(temp_storage)


def test_build_blob_name_simple():
    """build_blob_name should join components correctly."""
    result = cloud_storage.build_blob_name("file.txt")
    assert result == "file.txt"


def test_build_blob_name_with_prefix():
    """build_blob_name should prepend prefix correctly."""
    result = cloud_storage.build_blob_name("file.txt", prefix="user-data/session1")
    assert result == "user-data/session1/file.txt"


def test_build_blob_name_multiple_components():
    """build_blob_name should join multiple components."""
    result = cloud_storage.build_blob_name("subdir", "file.txt", prefix="data")
    assert result == "data/subdir/file.txt"


def test_build_blob_name_empty_raises():
    """build_blob_name should raise for empty components."""
    with pytest.raises(ValueError, match="Invalid blob path"):
        cloud_storage.build_blob_name("")


def test_upload_and_download_bytes(temp_storage):
    """upload_bytes and download_bytes should work together."""
    blob_name = "test/data.bin"
    data = b"hello world"

    cloud_storage.upload_bytes(blob_name, data)

    result = cloud_storage.download_bytes(blob_name)
    assert result == data


def test_upload_creates_directories(temp_storage):
    """upload_bytes should create parent directories as needed."""
    blob_name = "deep/nested/path/file.txt"
    data = b"test data"

    cloud_storage.upload_bytes(blob_name, data)

    expected_path = os.path.join(temp_storage, "deep", "nested", "path", "file.txt")
    assert os.path.isfile(expected_path)


def test_download_missing_returns_none(temp_storage):
    """download_bytes should return None for missing files."""
    result = cloud_storage.download_bytes("nonexistent/file.txt")
    assert result is None


def test_delete_blob(temp_storage):
    """delete_blob should remove the file."""
    blob_name = "to_delete.txt"
    cloud_storage.upload_bytes(blob_name, b"data")

    assert cloud_storage.blob_exists(blob_name)

    cloud_storage.delete_blob(blob_name)

    assert not cloud_storage.blob_exists(blob_name)


def test_delete_blob_missing_ok(temp_storage):
    """delete_blob with missing_ok=True should not raise for missing files."""
    cloud_storage.delete_blob("nonexistent.txt", missing_ok=True)


def test_delete_blob_missing_raises(temp_storage):
    """delete_blob with missing_ok=False should raise for missing files."""
    with pytest.raises(FileNotFoundError):
        cloud_storage.delete_blob("nonexistent.txt", missing_ok=False)


def test_list_blob_names(temp_storage):
    """list_blob_names should list all files under a prefix."""
    # Create some test files
    cloud_storage.upload_bytes("prefix/file1.txt", b"1")
    cloud_storage.upload_bytes("prefix/file2.txt", b"2")
    cloud_storage.upload_bytes("prefix/subdir/file3.txt", b"3")
    cloud_storage.upload_bytes("other/file4.txt", b"4")

    names = sorted(cloud_storage.list_blob_names("prefix"))

    assert "prefix/file1.txt" in names
    assert "prefix/file2.txt" in names
    assert "prefix/subdir/file3.txt" in names
    assert "other/file4.txt" not in names


def test_list_blob_names_empty_prefix(temp_storage):
    """list_blob_names with empty prefix should list all files."""
    cloud_storage.upload_bytes("file1.txt", b"1")
    cloud_storage.upload_bytes("dir/file2.txt", b"2")

    names = sorted(cloud_storage.list_blob_names(""))

    assert "file1.txt" in names
    assert "dir/file2.txt" in names


def test_blob_exists(temp_storage):
    """blob_exists should return True for existing files."""
    blob_name = "exists.txt"

    assert not cloud_storage.blob_exists(blob_name)

    cloud_storage.upload_bytes(blob_name, b"data")

    assert cloud_storage.blob_exists(blob_name)


def test_blob_updated_timestamp(temp_storage):
    """blob_updated_timestamp should return the file modification time."""
    blob_name = "timestamped.txt"

    assert cloud_storage.blob_updated_timestamp(blob_name) is None

    cloud_storage.upload_bytes(blob_name, b"data")

    timestamp = cloud_storage.blob_updated_timestamp(blob_name)
    assert isinstance(timestamp, float)
    assert timestamp > 0


def test_resolve_path_rejects_directory_traversal(temp_storage):
    """_resolve_path should reject paths that escape the storage directory."""
    with pytest.raises(ValueError, match="Invalid blob name"):
        cloud_storage._resolve_path("../escape.txt")

    with pytest.raises(ValueError, match="Invalid blob name"):
        cloud_storage._resolve_path("/absolute/path.txt")
