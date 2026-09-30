from __future__ import annotations

from datetime import datetime, timezone

import itsdangerous
from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry
from flask import g, session

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.webauthn.metadata import effective as metadata_effective
from server.app.webauthn.metadata import entries as metadata_entries
from server.app.webauthn.metadata import verifier as metadata_verifier
from tests.app.entry_app import entry_app


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
    reports = metadata_entries._normalise_status_reports(
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

    identifiers = metadata_entries._normalise_attestation_identifiers(
        {"attestationCertificateKeyIdentifiers": [" id-1 ", "", 1, "id-2"]}
    )
    assert identifiers == ["id-1", "id-2"]

    statement, legal = metadata_entries._normalise_metadata_statement(
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


def test_aaguid_extraction_merge_and_source_info_helpers(monkeypatch, entries):
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

    session_entry = MetadataBlobPayloadEntry.from_dict(session_payload)
    base_entry_same = MetadataBlobPayloadEntry.from_dict(base_payload_same)
    base_entry_other = MetadataBlobPayloadEntry.from_dict(base_payload_other)

    assert (
        metadata_entries._normalise_aaguid(" AAAA-BBBB-CCCC-DDDD-EEEEFFFF0000 ")
        == "aaaabbbbccccddddeeeeffff0000"
    )
    assert metadata_entries._extract_entry_aaguid(session_entry) is None

    class _MappingBackedEntry:
        aaguid = None
        metadata_statement = {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}

    assert (
        metadata_entries._extract_entry_aaguid(_MappingBackedEntry())
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

    base_metadata = MetadataBlobPayload(
        legal_header="",
        no=7,
        next_update=datetime.now(timezone.utc).date(),
        entries=(base_entry_same, base_entry_other),
    )

    monkeypatch.setattr(
        entries,
        "_extract_entry_aaguid",
        lambda entry: metadata_entries._normalise_aaguid(str(getattr(entry, "aaguid", ""))),
    )

    merged = metadata_verifier._merge_metadata(base_metadata, [session_item])
    merged_descriptions = [entry["metadataStatement"]["description"] for entry in merged.entries]
    assert merged_descriptions == ["Session metadata", "Base unique"]
    assert merged.legal_header == "Session Legal"

    source_info = metadata_effective._session_item_source_info(session_item)
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


def test_prune_helper_and_request_session_identifier_paths(monkeypatch, tmp_path, session_store, app_config):
    # Resolving the cookie's namespace refreshes its directory's last-access marker.
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))

    monkeypatch.setattr(
        session_store,
        "prune_session",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("ignore prune errors")),
    )
    mds_uploads._prune_session_metadata_directory("session-1")

    # Only a cookie signed with the application secret names a namespace; an
    # unsigned one is ignored (it would otherwise be an IDOR).
    sealed = itsdangerous.URLSafeTimedSerializer(
        entry_app().secret_key, salt="fido.mds.session-cookie.v1"
    ).dumps("cookie-session")
    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}=cookie-session"},
    ):
        assert visitor_session.current_id(create=False) is None

    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}={sealed}"},
    ):
        identifier = visitor_session.current_id(create=False)
        assert identifier == "cookie-session"
        assert session[visitor_session.SESSION_KEY] == "cookie-session"
        assert g._session_metadata_cookie == "cookie-session"

    with entry_app().test_request_context("/"):
        generated = visitor_session.current_id(create=True)
        assert isinstance(generated, str)
        assert session[visitor_session.SESSION_KEY] == generated
        assert g._session_metadata_cookie == generated

    with entry_app().test_request_context("/"):
        assert visitor_session.current_id(create=False) is None
