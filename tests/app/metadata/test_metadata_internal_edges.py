import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


@pytest.fixture
def metadata_module(monkeypatch):
    module = pytest.importorskip("server.app.metadata")

    monkeypatch.setattr(module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_explorer_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_full_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(module, "_base_verifier_mtime", None, raising=False)

    return module


def test_env_flag_cleanup_async_and_interval_resolution(metadata_module, monkeypatch):
    monkeypatch.delenv(metadata_module._SESSION_METADATA_CLEANUP_ASYNC_ENV, raising=False)
    assert metadata_module._cleanup_async_enabled() is True

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_ASYNC_ENV, "off")
    assert metadata_module._cleanup_async_enabled() is False

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "30")
    assert metadata_module._resolve_cleanup_interval().total_seconds() == 30

    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV, "invalid")
    monkeypatch.setenv(metadata_module._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV, "2")
    assert metadata_module._resolve_cleanup_interval().total_seconds() == 2 * 3600


def test_safe_filename_and_upload_flow_handles_skip_update_and_disabled_logging(metadata_module, monkeypatch):
    content = b"metadata-payload"

    uploads = []
    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: True, raising=False)
    monkeypatch.setattr(metadata_module, "git_blob_sha", lambda _content: "sha-content", raising=False)

    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda _folder: [{"type": "file", "name": "metadata.json", "sha": "sha-content"}],
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "github_upload_file",
        lambda *args, **kwargs: uploads.append((args, kwargs)),
        raising=False,
    )

    assert metadata_module.maybe_store_uploaded_metadata_file("metadata.json", content) is False
    assert uploads == []

    monkeypatch.setattr(
        metadata_module,
        "github_list_directory",
        lambda _folder: [
            {
                "type": "file",
                "name": "metadata.json",
                "sha": "old-sha",
                "path": "metadata/metadata.json",
            }
        ],
        raising=False,
    )

    assert metadata_module.maybe_store_uploaded_metadata_file(" metadata.json ", content) is True
    assert uploads and uploads[-1][0][0] == "metadata/metadata.json"
    assert uploads[-1][0][2] == "metadata: update metadata.json"
    assert uploads[-1][1]["sha"] == "old-sha"

    monkeypatch.setattr(metadata_module, "is_logging_enabled", lambda: False, raising=False)
    assert metadata_module.maybe_store_uploaded_metadata_file("metadata.json", content) is False


def test_session_identifier_and_filename_validation_helpers(metadata_module):
    assert metadata_module._normalise_session_identifier("  session-1  ") == "session-1"
    assert metadata_module._normalise_session_identifier(123) is None
    assert metadata_module._normalise_session_identifier(".hidden") is None
    assert metadata_module._normalise_session_identifier("a/b") is None

    assert metadata_module._validate_session_metadata_filename("entry.json") == "entry.json"

    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename("../entry.json")
    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename(".entry.json")
    with pytest.raises(ValueError):
        metadata_module._validate_session_metadata_filename("entry.txt")


def test_load_session_metadata_info_and_clone_helpers(metadata_module, monkeypatch):
    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "read_file",
        lambda _sid, _name: b'{"uploaded_at":"now"}',
        raising=False,
    )
    assert metadata_module._load_session_metadata_info("session", "entry.meta.json") == {
        "uploaded_at": "now"
    }

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "read_file",
        lambda _sid, _name: b"not-json",
        raising=False,
    )
    assert metadata_module._load_session_metadata_info("session", "entry.meta.json") == {}

    assert metadata_module._clone_json_value({"a": [1, 2]}) == {"a": [1, 2]}
    assert metadata_module._clone_json_value(object()) is None


def test_build_metadata_entry_components_and_expand_payloads(metadata_module):
    raw = {
        "legalHeader": "Demo legal",
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": "Demo authenticator",
        },
        "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}],
    }

    entry, legal_header, payload = metadata_module.build_metadata_entry_components(raw)

    assert legal_header == "Demo legal"
    assert payload["metadataStatement"]["description"] == "Demo authenticator"
    assert payload["metadataStatement"]["attestationRootCertificates"] == []
    assert payload["statusReports"][0]["status"] == "NOT_FIDO_CERTIFIED"
    assert entry["metadataStatement"]["description"] == "Demo authenticator"

    expanded = metadata_module.expand_metadata_entry_payloads(
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
        metadata_module.expand_metadata_entry_payloads({"entries": []})

    with pytest.raises(ValueError, match="is not a JSON object"):
        metadata_module.expand_metadata_entry_payloads({"entries": ["bad-entry"]})


def test_entry_lookup_and_snapshot_composition_deduplicate_by_aaguid(metadata_module, monkeypatch):
    payload = {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "aaid": "A1B2#0001",
        "metadataStatement": {"description": "Entry"},
    }
    entry_id = metadata_module.build_entry_id(payload)

    assert metadata_module._entry_matches_lookup(payload, entry_id=entry_id) is True
    assert (
        metadata_module._entry_matches_lookup(
            payload, aaguid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        is True
    )
    assert metadata_module._entry_matches_lookup(payload, aaid="A1B2#0001") is True

    base_snapshot = {
        "meta": {"entryCount": 2},
        "entries": [
            {"entryId": "base-1", "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {"entryId": "base-2", "aaguid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        ],
    }

    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: [object()], raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_build_session_snapshot_entry",
        lambda *_args, **_kwargs: {
            "entryId": "session-1",
            "source": "session",
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
        raising=False,
    )

    snapshot = metadata_module._compose_effective_snapshot(base_snapshot, include_detail=False)

    assert snapshot["meta"]["entryCount"] == 2
    assert snapshot["meta"]["customEntryCount"] == 1
    assert snapshot["entries"][0]["source"] == "session"
    assert [entry["entryId"] for entry in snapshot["entries"]] == ["session-1", "base-2"]


def test_load_base_explorer_snapshot_prefers_packaged_explorer_when_newer(metadata_module, monkeypatch, tmp_path):
    verified_path = tmp_path / "verified.json"
    explorer_path = tmp_path / "explorer.json"

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

    monkeypatch.setattr(metadata_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_EXPLORER_PATH", str(explorer_path), raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_mtime", None, raising=False)

    snapshot, marker = metadata_module._load_base_explorer_snapshot()

    assert snapshot["meta"]["entryCount"] == 1
    assert marker is not None


def test_load_packaged_explorer_summary_and_get_mds_verifier_cache_paths(metadata_module, monkeypatch):
    monkeypatch.setattr(metadata_module, "_load_base_explorer_snapshot", lambda: (None, None), raising=False)
    monkeypatch.setattr(
        metadata_module,
        "_load_verified_metadata_payload",
        lambda: {"legalHeader": "L", "no": 1, "nextUpdate": "2099-01-01", "entries": []},
        raising=False,
    )
    monkeypatch.setattr(
        metadata_module,
        "build_explorer_snapshot",
        lambda payload, _cache: {"meta": {"entryCount": len(payload.get("entries", []))}},
        raising=False,
    )

    summary = metadata_module.load_packaged_explorer_summary()
    assert summary["entryCount"] == 0

    created = []

    class _FakeVerifier:
        def __init__(self, metadata):
            self.metadata = metadata
            created.append(metadata)

    fake_metadata = SimpleNamespace(entries=[])
    monkeypatch.setattr(metadata_module, "_load_base_metadata", lambda: (fake_metadata, 123.0), raising=False)
    monkeypatch.setattr(metadata_module, "list_session_metadata_items", lambda: [], raising=False)
    monkeypatch.setattr(metadata_module, "MdsAttestationVerifier", _FakeVerifier, raising=False)

    first = metadata_module.get_mds_verifier()
    second = metadata_module.get_mds_verifier()

    assert first is second
    assert created == [fake_metadata]


def test_metadata_entry_trust_anchor_status_uses_session_and_base_entry_sets(metadata_module):
    entry = metadata_module.MetadataBlobPayloadEntry.from_dict(
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

    metadata_module._session_metadata_entry_ids = {id(entry)}
    metadata_module._base_metadata_entry_ids = set()
    metadata_module._base_metadata_trust_verified = True
    assert metadata_module.metadata_entry_trust_anchor_status(entry) is False

    metadata_module._session_metadata_entry_ids = set()
    metadata_module._base_metadata_entry_ids = {id(entry)}
    metadata_module._base_metadata_trust_verified = True
    assert metadata_module.metadata_entry_trust_anchor_status(entry) is True
