from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from flask import g, session


def _entry_payload(*, aaguid: str, description: str):
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": description,
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


def test_metadata_normalisation_helpers_cover_status_identifiers_and_defaults():
    metadata_module = pytest.importorskip("server.app.metadata")

    reports = metadata_module._normalise_status_reports(
        {
            "statusReports": [
                {"status": "NOT_FIDO_CERTIFIED"},
                "skip",
                {"status": "FIDO_CERTIFIED"},
            ]
        }
    )
    assert reports == [
        {"status": "NOT_FIDO_CERTIFIED"},
        {"status": "FIDO_CERTIFIED"},
    ]

    identifiers = metadata_module._normalise_attestation_identifiers(
        {"attestationCertificateKeyIdentifiers": [" id-1 ", "", 1, "id-2"]}
    )
    assert identifiers == ["id-1", "id-2"]

    statement, legal = metadata_module._normalise_metadata_statement(
        {
            "legalHeader": " Demo legal ",
            "metadataStatement": {
                "description": 123,
                "authenticatorVersion": "bad",
                "schema": "bad",
            },
        }
    )
    assert legal == "Demo legal"
    assert statement["legalHeader"] == "Demo legal"
    assert statement["description"] == ""
    assert statement["authenticatorVersion"] == 0
    assert statement["schema"] == 3
    assert isinstance(statement["attestationRootCertificates"], list)


def test_aaguid_extraction_merge_and_source_info_helpers(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    session_payload = _entry_payload(
        aaguid="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        description="Session metadata",
    )
    base_payload_same = _entry_payload(
        aaguid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        description="Base duplicate",
    )
    base_payload_other = _entry_payload(
        aaguid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        description="Base unique",
    )

    session_entry = metadata_module.MetadataBlobPayloadEntry.from_dict(session_payload)
    base_entry_same = metadata_module.MetadataBlobPayloadEntry.from_dict(base_payload_same)
    base_entry_other = metadata_module.MetadataBlobPayloadEntry.from_dict(base_payload_other)

    assert (
        metadata_module._normalise_aaguid(" AAAA-BBBB-CCCC-DDDD-EEEEFFFF0000 ")
        == "aaaabbbbccccddddeeeeffff0000"
    )
    assert metadata_module._extract_entry_aaguid(session_entry) is None

    class _MappingBackedEntry:
        aaguid = None
        metadata_statement = {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}

    assert (
        metadata_module._extract_entry_aaguid(_MappingBackedEntry())
        == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    session_item = metadata_module.SessionMetadataItem(
        filename="session.json",
        payload=session_payload,
        legal_header="Session Legal",
        entry=session_entry,
        uploaded_at="2026-04-03T00:00:00+00:00",
        original_filename="upload.json",
        mtime=1.0,
    )

    base_metadata = metadata_module.MetadataBlobPayload(
        legal_header="",
        no=7,
        next_update=datetime.now(timezone.utc).date(),
        entries=(base_entry_same, base_entry_other),
    )

    monkeypatch.setattr(
        metadata_module,
        "_extract_entry_aaguid",
        lambda entry: metadata_module._normalise_aaguid(str(getattr(entry, "aaguid", ""))),
        raising=False,
    )

    merged = metadata_module._merge_metadata(base_metadata, [session_item])
    merged_descriptions = [entry["metadataStatement"]["description"] for entry in merged.entries]
    assert merged_descriptions == ["Session metadata", "Base unique"]
    assert merged.legal_header == "Session Legal"

    source_info = metadata_module._session_item_source_info(session_item)
    assert source_info["storedFilename"] == "session.json"
    assert source_info["originalFilename"] == "upload.json"
    assert source_info["uploadedAt"] == "2026-04-03T00:00:00+00:00"
    assert "modifiedAt" in source_info


def test_cache_cleaning_formatting_and_store_helper(tmp_path, monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")

    assert metadata_module._clean_metadata_cache_value("  etag-value  ") == "etag-value"
    assert metadata_module._clean_metadata_cache_value("   ") is None

    iso_value = metadata_module._format_last_modified("Wed, 21 Oct 2015 07:28:00 GMT")
    assert iso_value == "2015-10-21T07:28:00+00:00"
    assert metadata_module._format_last_modified("not-a-date") == "not-a-date"

    cache_path = tmp_path / "cache" / "metadata-cache.json"
    monkeypatch.setattr(metadata_module, "MDS_METADATA_CACHE_PATH", str(cache_path), raising=False)

    metadata_module._store_metadata_cache_entry(
        last_modified_header="Wed, 21 Oct 2015 07:28:00 GMT",
        last_modified_iso="2015-10-21T07:28:00+00:00",
        etag="abc123",
    )

    stored = json.loads(cache_path.read_text(encoding="utf-8"))
    assert stored["last_modified"] == "Wed, 21 Oct 2015 07:28:00 GMT"
    assert stored["last_modified_iso"] == "2015-10-21T07:28:00+00:00"
    assert stored["etag"] == "abc123"
    assert stored["fetched_at"]


def test_prune_helper_and_request_session_identifier_paths(monkeypatch):
    metadata_module = pytest.importorskip("server.app.metadata")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(
        metadata_module.session_metadata_store,
        "prune_session",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("ignore prune errors")),
        raising=False,
    )
    metadata_module._prune_session_metadata_directory("session-1")

    with config_module.app.test_request_context(
        "/",
        headers={"Cookie": f"{metadata_module._SESSION_METADATA_COOKIE_NAME}=cookie-session"},
    ):
        identifier = metadata_module._get_metadata_session_id(create=False)
        assert identifier == "cookie-session"
        assert session[metadata_module._SESSION_METADATA_SESSION_KEY] == "cookie-session"
        assert g._session_metadata_cookie == "cookie-session"

    with config_module.app.test_request_context("/"):
        generated = metadata_module._get_metadata_session_id(create=True)
        assert isinstance(generated, str)
        assert session[metadata_module._SESSION_METADATA_SESSION_KEY] == generated
        assert g._session_metadata_cookie == generated

    with config_module.app.test_request_context("/"):
        assert metadata_module._get_metadata_session_id(create=False) is None
