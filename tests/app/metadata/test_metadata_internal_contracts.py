import os

from server.app.storage import common as storage_common
from server.app.storage import github_mirror


def test_normalise_session_identifier_rejects_path_separators(monkeypatch):
    assert storage_common.normalise_session_id("session/abc") is None

    monkeypatch.setattr(os, "altsep", "\\")
    assert storage_common.normalise_session_id("session\\abc") is None


def test_normalise_session_identifier_accepts_clean_value_and_rejects_invalid_shapes():
    assert (
        storage_common.normalise_session_id(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        == "550e8400-e29b-41d4-a716-446655440000"
    )
    assert storage_common.normalise_session_id("  session-1  ") == "session-1"
    assert storage_common.normalise_session_id("   ") is None
    assert storage_common.normalise_session_id(".hidden") is None
    assert storage_common.normalise_session_id(123) is None


def test_safe_metadata_repo_filename_sanitizes_traversal_and_invalid_input():
    assert github_mirror._safe_metadata_repo_filename("../../../etc/passwd") == "passwd"
    assert github_mirror._safe_metadata_repo_filename(" /tmp/demo.json ") == "demo.json"
    assert github_mirror._safe_metadata_repo_filename("///") == "metadata.json"
    assert github_mirror._safe_metadata_repo_filename(None) == "metadata.json"


def test_maybe_store_uploaded_metadata_file_returns_false_when_logging_disabled(monkeypatch):
    listed = []
    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: False)
    monkeypatch.setattr(
        github_mirror,
        "github_list_directory",
        lambda *_args, **_kwargs: listed.append(True),
    )

    stored = github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}")

    assert stored is False
    assert listed == []


def test_maybe_store_uploaded_metadata_file_skips_upload_when_identical_sha_exists(monkeypatch):
    content = b'{"entry":1}'
    blob_sha = "same-blob-sha"
    upload_calls = []

    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(github_mirror, "git_blob_sha", lambda _content: blob_sha)
    monkeypatch.setattr(
        github_mirror,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "existing.json",
                "path": "metadata/existing.json",
                "sha": blob_sha,
            }
        ],
    )
    monkeypatch.setattr(
        github_mirror,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
    )

    stored = github_mirror.maybe_store_uploaded_metadata_file("demo.json", content)

    assert stored is False
    assert upload_calls == []


def test_maybe_store_uploaded_metadata_file_updates_existing_name_with_sha(monkeypatch):
    content = b'{"entry":2}'
    upload_calls = []

    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(github_mirror, "git_blob_sha", lambda _content: "new-sha")
    monkeypatch.setattr(
        github_mirror,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "demo.json",
                "path": "metadata/demo.json",
                "sha": "old-sha",
            }
        ],
    )
    monkeypatch.setattr(
        github_mirror,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
    )

    stored = github_mirror.maybe_store_uploaded_metadata_file("demo.json", content)

    assert stored is True
    assert len(upload_calls) == 1
    args, kwargs = upload_calls[0]
    assert args[0] == "metadata/demo.json"
    assert args[1] == content
    assert args[2] == "metadata: update demo.json"
    assert kwargs == {"sha": "old-sha"}


def test_maybe_store_uploaded_metadata_file_adds_new_file_with_sanitized_name(monkeypatch):
    content = b'{"entry":3}'
    upload_calls = []

    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(github_mirror, "git_blob_sha", lambda _content: "fresh-sha")
    monkeypatch.setattr(github_mirror, "github_list_directory", lambda _folder: [])
    monkeypatch.setattr(
        github_mirror,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
    )

    stored = github_mirror.maybe_store_uploaded_metadata_file("../../../custom.json", content)

    assert stored is True
    assert len(upload_calls) == 1
    args, kwargs = upload_calls[0]
    assert args[0] == "metadata/custom.json"
    assert args[1] == content
    assert args[2] == "metadata: add custom.json"
    assert kwargs == {"sha": None}
