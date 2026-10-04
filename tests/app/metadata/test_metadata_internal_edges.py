import json
import os
from datetime import datetime, timezone

import pytest

from server.app.mds import cache as mds_cache
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.storage import common as storage_common
from server.app.storage import github_mirror, session_metadata


def test_safe_filename_and_upload_flow_handles_skip_update_and_disabled_logging(metadata_state, monkeypatch):
    content = b"metadata-payload"

    recorded = []
    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(github_mirror, "git_blob_sha", lambda _content: "sha-content")

    monkeypatch.setattr(
        github_mirror,
        "github_list_directory",
        lambda _folder: [{"type": "file", "name": "metadata.json", "sha": "sha-content"}],
    )
    monkeypatch.setattr(
        github_mirror,
        "github_upload_file",
        lambda *args, **kwargs: recorded.append((args, kwargs)),
    )

    assert github_mirror.maybe_store_uploaded_metadata_file("metadata.json", content) is False
    assert recorded == []

    monkeypatch.setattr(
        github_mirror,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "metadata.json",
                "sha": "old-sha",
                "path": "metadata/metadata.json",
            }
        ],
    )

    assert github_mirror.maybe_store_uploaded_metadata_file(" metadata.json ", content) is True
    assert recorded and recorded[-1][0][0] == "metadata/metadata.json"
    assert recorded[-1][0][2] == "metadata: update metadata.json"
    assert recorded[-1][1]["sha"] == "old-sha"

    monkeypatch.setattr(github_mirror, "is_logging_enabled", lambda: False)
    assert github_mirror.maybe_store_uploaded_metadata_file("metadata.json", content) is False


def test_session_identifier_and_filename_validation_helpers(metadata_state):
    assert storage_common.normalise_session_id("  session-1  ") == "session-1"
    assert storage_common.normalise_session_id(123) is None
    assert storage_common.normalise_session_id(".hidden") is None
    assert storage_common.normalise_session_id("a/b") is None

    assert mds_uploads._validate_session_metadata_filename("entry.json") == "entry.json"

    with pytest.raises(ValueError):
        mds_uploads._validate_session_metadata_filename("../entry.json")
    with pytest.raises(ValueError):
        mds_uploads._validate_session_metadata_filename(".entry.json")
    with pytest.raises(ValueError):
        mds_uploads._validate_session_metadata_filename("entry.txt")


def test_load_session_metadata_info_and_clone_helpers(metadata_state, monkeypatch):
    monkeypatch.setattr(
        session_metadata,
        "read_file",
        lambda _sid, _name: b'{"uploaded_at":"now"}',
    )
    assert mds_uploads._load_session_metadata_info("session", "entry.meta.json") == {
        "uploaded_at": "now"
    }

    monkeypatch.setattr(
        session_metadata,
        "read_file",
        lambda _sid, _name: b"not-json",
    )
    assert mds_uploads._load_session_metadata_info("session", "entry.meta.json") == {}

    assert mds_entries._clone_json_value({"a": [1, 2]}) == {"a": [1, 2]}
    assert mds_entries._clone_json_value(object()) is None


def test_build_metadata_entry_components_and_expand_payloads(metadata_state):
    raw = {
        "legalHeader": "Demo legal",
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": "Demo authenticator",
        },
        "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}],
    }

    entry, legal_header, payload = mds_entries.build_metadata_entry_components(raw)

    assert legal_header == "Demo legal"
    assert payload["metadataStatement"]["description"] == "Demo authenticator"
    assert payload["metadataStatement"]["attestationRootCertificates"] == []
    assert payload["statusReports"][0]["status"] == "NOT_FIDO_CERTIFIED"
    assert entry["metadataStatement"]["description"] == "Demo authenticator"

    expanded = mds_entries.expand_metadata_entry_payloads(
        {
            "legalHeader": "Bulk legal",
            "entries": [
                {"metadataStatement": {"description": "First"}},
                {"metadataStatement": {"description": "Second"}},
            ],
        }
    )
    assert len(expanded) == 2
    assert all(item.get("legalHeader") == "Bulk legal" for item in expanded)

    with pytest.raises(ValueError, match="does not contain any entries"):
        mds_entries.expand_metadata_entry_payloads({"entries": []})

    with pytest.raises(ValueError, match="is not a JSON object"):
        mds_entries.expand_metadata_entry_payloads({"entries": ["bad-entry"]})


def test_load_base_explorer_snapshot_prefers_packaged_explorer_when_newer(monkeypatch, tmp_path, metadata_state):
    verified_path = tmp_path / "fido-mds3.verified.json"
    explorer_path = tmp_path / "fido-mds3.explorer.json"

    verified_path.write_text(
        json.dumps({"legalHeader": "L", "no": 1, "nextUpdate": "2099-01-01", "entries": []}),
        encoding="utf-8",
    )
    explorer_path.write_text(
        json.dumps({"meta": {"entryCount": 1, "source": "packaged"}, "entries": [{"entryId": "x"}]}),
        encoding="utf-8",
    )

    now = datetime.now(timezone.utc).timestamp()
    os.utime(verified_path, (now - 10, now - 10))
    os.utime(explorer_path, (now, now))

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    monkeypatch.setattr(mds_cache.CACHE, "explorer", None)
    monkeypatch.setattr(mds_cache.CACHE, "explorer_mtime", None)

    snapshot, marker = mds_cache._load_base_explorer_snapshot()

    assert snapshot["meta"]["entryCount"] == 1
    assert marker is not None
