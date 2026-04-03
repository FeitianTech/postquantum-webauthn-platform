from datetime import timedelta

import pytest


def test_resolve_cleanup_interval_prefers_seconds_over_hours(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "15")
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV, "2")

    interval = metadata_module._resolve_cleanup_interval()

    assert interval == timedelta(seconds=15)


def test_resolve_cleanup_interval_uses_hours_when_seconds_invalid(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "not-a-number")
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV, "1.5")

    interval = metadata_module._resolve_cleanup_interval()

    assert interval == timedelta(hours=1.5)


def test_resolve_cleanup_interval_defaults_when_all_config_values_negative(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "-3")
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV, "-1")

    interval = metadata_module._resolve_cleanup_interval()

    assert interval == timedelta(hours=6)


def test_normalise_session_identifier_rejects_path_separators(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    assert metadata_module._normalise_session_identifier("session/abc") is None

    monkeypatch.setattr(metadata_module.os, "altsep", "\\", raising=False)
    assert metadata_module._normalise_session_identifier("session\\abc") is None


def test_normalise_session_identifier_accepts_clean_value_and_rejects_invalid_shapes():
    metadata_module = pytest.importorskip("server.app.metadata")

    assert (
        metadata_module._normalise_session_identifier(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        == "550e8400-e29b-41d4-a716-446655440000"
    )
    assert metadata_module._normalise_session_identifier("   ") is None
    assert metadata_module._normalise_session_identifier(".hidden") is None
    assert metadata_module._normalise_session_identifier(123) is None


def test_safe_metadata_repo_filename_sanitizes_traversal_and_invalid_input():
    metadata_module = pytest.importorskip("server.app.metadata")

    assert metadata_module._safe_metadata_repo_filename("../../../etc/passwd") == "passwd"
    assert metadata_module._safe_metadata_repo_filename(" /tmp/demo.json ") == "demo.json"
    assert metadata_module._safe_metadata_repo_filename("///") == "metadata.json"
    assert metadata_module._safe_metadata_repo_filename(None) == "metadata.json"


def test_maybe_store_uploaded_metadata_file_returns_false_when_logging_disabled(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    listed = []
    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: False, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda *_args, **_kwargs: listed.append(True),
        raising=False,
    )

    stored = metadata_module.maybe_store_uploaded_metadata_file("demo.json", b"{}")

    assert stored is False
    assert listed == []


def test_maybe_store_uploaded_metadata_file_skips_upload_when_identical_sha_exists(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    content = b'{"entry":1}'
    blob_sha = "same-blob-sha"
    upload_calls = []

    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: True, raising=False)
    monkeypatch.setattr(metadata_module, "git_blob_sha", lambda _content: blob_sha, raising=False)
    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "existing.json",
                "path": "metadata/existing.json",
                "sha": blob_sha,
            }
        ],
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
        raising=False,
    )

    stored = metadata_module.maybe_store_uploaded_metadata_file("demo.json", content)

    assert stored is False
    assert upload_calls == []


def test_maybe_store_uploaded_metadata_file_updates_existing_name_with_sha(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    content = b'{"entry":2}'
    upload_calls = []

    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: True, raising=False)
    monkeypatch.setattr(metadata_module, "git_blob_sha", lambda _content: "new-sha", raising=False)
    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "demo.json",
                "path": "metadata/demo.json",
                "sha": "old-sha",
            }
        ],
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
        raising=False,
    )

    stored = metadata_module.maybe_store_uploaded_metadata_file("demo.json", content)

    assert stored is True
    assert len(upload_calls) == 1
    args, kwargs = upload_calls[0]
    assert args[0] == "metadata/demo.json"
    assert args[1] == content
    assert args[2] == "metadata: update demo.json"
    assert kwargs == {"sha": "old-sha"}


def test_maybe_store_uploaded_metadata_file_adds_new_file_with_sanitized_name(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    content = b'{"entry":3}'
    upload_calls = []

    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: True, raising=False)
    monkeypatch.setattr(metadata_module, "git_blob_sha", lambda _content: "fresh-sha", raising=False)
    monkeypatch.setattr(metadata_module, "github_list_directory", lambda _folder: [], raising=False)
    monkeypatch.setattr(
        metadata_module,
        "github_upload_file",
        lambda *args, **kwargs: upload_calls.append((args, kwargs)),
        raising=False,
    )

    stored = metadata_module.maybe_store_uploaded_metadata_file("../../../custom.json", content)

    assert stored is True
    assert len(upload_calls) == 1
    args, kwargs = upload_calls[0]
    assert args[0] == "metadata/custom.json"
    assert args[1] == content
    assert args[2] == "metadata: add custom.json"
    assert kwargs == {"sha": None}
