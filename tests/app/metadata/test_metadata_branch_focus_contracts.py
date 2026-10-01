from __future__ import annotations

import pytest

from server.app.storage import github_mirror


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    """A fresh MDS cache and sweep state."""

    """A fresh MDS cache and sweep state."""


def _minimal_entry_payload(*, aaguid: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") -> dict:
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": "Demo",
            "authenticatorVersion": 1,
            "schema": 3,
            "upv": [],
            "attestationTypes": [],
            "userVerificationDetails": [],
            "keyProtection": [],
            "matcherProtection": [],
            "attachmentHint": [],
            "tcDisplay": [],
            "attestationRootCertificates": [],
        },
    }



def test_upload_and_normalisation_error_edges(metadata_module, monkeypatch, uploads, sessions):
    recorded = []
    monkeypatch.setattr(uploads, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(uploads, "git_blob_sha", lambda _content: "new-sha")
    monkeypatch.setattr(
        uploads,
        "github_list_directory",
        lambda _folder: [
            123,
            {"type": "dir", "name": "not-a-file"},
            {"type": "file", "name": "target.json", "sha": "old-sha", "path": 99},
        ],
    )
    monkeypatch.setattr(
        uploads,
        "github_upload_file",
        lambda *args, **kwargs: recorded.append((args, kwargs)),
    )

    assert github_mirror.maybe_store_uploaded_metadata_file("target.json", b"{}") is True
    assert recorded[0][0][0] == "metadata/target.json"
    assert recorded[0][1] == {"sha": "old-sha"}
