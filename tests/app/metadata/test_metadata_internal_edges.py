import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry

from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import uploads as mds_uploads
from server.app.mds import verifier as mds_verifier
from server.app.storage import common as storage_common
from server.app.storage import github_mirror, session_metadata


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    """A fresh MDS cache and sweep state."""

    """A fresh MDS cache and sweep state."""


def test_safe_filename_and_upload_flow_handles_skip_update_and_disabled_logging(metadata_module, monkeypatch):
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


def test_session_identifier_and_filename_validation_helpers(metadata_module):
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


def test_load_session_metadata_info_and_clone_helpers(metadata_module, monkeypatch):
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


def test_build_metadata_entry_components_and_expand_payloads(metadata_module):
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


def test_entry_lookup_and_snapshot_composition_deduplicate_by_aaguid(metadata_module, monkeypatch):
    payload = {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "aaid": "A1B2#0001",
        "metadataStatement": {"description": "Entry"},
    }
    entry_id = mds_effective.build_entry_id(payload)

    assert mds_effective._entry_matches_lookup(payload, entry_id=entry_id) is True
    assert (
        mds_effective._entry_matches_lookup(
            payload, aaguid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        is True
    )
    assert mds_effective._entry_matches_lookup(payload, aaid="A1B2#0001") is True

    base_snapshot = {
        "meta": {"entryCount": 2},
        "entries": [
            {"entryId": "base-1", "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {"entryId": "base-2", "aaguid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        ],
    }

    monkeypatch.setattr(mds_uploads, "list_session_metadata_items", lambda: [object()])
    monkeypatch.setattr(
        mds_effective,
        "_build_session_snapshot_entry",
        lambda *_args, **_kwargs: {
            "entryId": "session-1",
            "source": "session",
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
    )

    snapshot = mds_effective._compose_effective_snapshot(base_snapshot, include_detail=False)

    assert snapshot["meta"]["entryCount"] == 2
    assert snapshot["meta"]["customEntryCount"] == 1
    assert snapshot["entries"][0]["source"] == "session"
    assert [entry["entryId"] for entry in snapshot["entries"]] == ["session-1", "base-2"]


def test_load_base_explorer_snapshot_prefers_packaged_explorer_when_newer(metadata_module, monkeypatch, tmp_path, metadata_state):
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


def test_load_packaged_explorer_summary_and_get_mds_verifier_cache_paths(metadata_module, monkeypatch):
    monkeypatch.setattr(mds_cache, "_load_packaged_explorer_meta", lambda: None)
    monkeypatch.setattr(mds_cache, "_load_base_explorer_snapshot", lambda: (None, None))
    monkeypatch.setattr(
        mds_cache,
        "_load_verified_metadata_payload",
        lambda: {"legalHeader": "L", "no": 1, "nextUpdate": "2099-01-01", "entries": []},
    )
    monkeypatch.setattr(
        mds_cache,
        "build_explorer_snapshot",
        lambda payload, _cache: {"meta": {"entryCount": len(payload.get("entries", []))}},
    )

    summary = mds_cache.load_packaged_explorer_summary()
    assert summary["entryCount"] == 0

    created = []

    class _FakeVerifier:
        def __init__(self, metadata):
            self.metadata = metadata
            created.append(metadata)

    fake_metadata = SimpleNamespace(entries=[])
    monkeypatch.setattr(mds_cache, "_load_base_metadata", lambda: (fake_metadata, 123.0))
    monkeypatch.setattr(mds_uploads, "list_session_metadata_items", lambda: [])
    monkeypatch.setattr(mds_verifier, "MdsAttestationVerifier", _FakeVerifier)

    first = mds_verifier.get_mds_verifier()
    second = mds_verifier.get_mds_verifier()

    assert first is second
    assert created == [fake_metadata]


def test_metadata_entry_trust_anchor_status_uses_session_and_base_entry_sets(metadata_module, metadata_state):
    entry = MetadataBlobPayloadEntry.from_dict(
        {
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
    )

    mds_cache.CACHE.entry_ids = {id(entry)}
    mds_cache.CACHE.trust_verified = True
    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is True
