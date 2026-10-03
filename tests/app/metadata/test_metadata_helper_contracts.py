from __future__ import annotations

from fido2.mds3 import MetadataBlobPayloadEntry

from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import entries as mds_entries
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata


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


def test_status_reports_keep_only_the_objects():
    reports = mds_entries._normalise_status_reports(
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


def test_attestation_key_identifiers_keep_only_trimmed_text():
    identifiers = mds_entries._normalise_attestation_identifiers(
        {"attestationCertificateKeyIdentifiers": [" id-1 ", "", 1, "id-2"]}
    )
    assert identifiers == ["id-1", "id-2"]


def test_a_statement_gets_the_legal_header_and_defaults_for_fields_that_do_not_read():
    statement, legal = mds_entries._normalise_metadata_statement(
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


def test_aaguid_extraction_and_source_info_helpers():
    session_payload = _entry_payload(
        aaguid="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        description="Session metadata",
    )

    session_entry = MetadataBlobPayloadEntry.from_dict(session_payload)

    assert (
        mds_entries._normalise_aaguid(" AAAA-BBBB-CCCC-DDDD-EEEEFFFF0000 ")
        == "aaaabbbbccccddddeeeeffff0000"
    )
    assert mds_entries._extract_entry_aaguid(session_entry) is None

    class _MappingBackedEntry:
        aaguid = None
        metadata_statement = {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}

    assert (
        mds_entries._extract_entry_aaguid(_MappingBackedEntry())
        == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    session_item = mds_uploads.SessionMetadataItem(
        filename="session.json",
        payload=session_payload,
        legal_header="Session Legal",
        entry=session_entry,
        uploaded_at="2026-04-03T00:00:00+00:00",
        original_filename="upload.json",
        mtime=1.0,
    )

    source_info = mds_effective._session_item_source_info(session_item)
    assert source_info["storedFilename"] == "session.json"
    assert source_info["originalFilename"] == "upload.json"
    assert source_info["uploadedAt"] == "2026-04-03T00:00:00+00:00"
    assert "modifiedAt" in source_info


def test_cache_cleaning_and_formatting_helpers():
    assert mds_cache._clean_metadata_cache_value("  etag-value  ") == "etag-value"
    assert mds_cache._clean_metadata_cache_value("   ") is None

    iso_value = mds_files.format_last_modified("Wed, 21 Oct 2015 07:28:00 GMT")
    assert iso_value == "2015-10-21T07:28:00+00:00"
    assert mds_files.format_last_modified("not-a-date") == "not-a-date"


def test_a_prune_that_fails_is_passed_over(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(
        session_metadata,
        "prune_session",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("ignore prune errors")),
    )

    mds_uploads._prune_session_metadata_directory("session-1")
