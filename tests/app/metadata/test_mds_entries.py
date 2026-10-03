"""``mds.entries``: an uploaded metadata statement read into a MetadataBlobPayloadEntry."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry

from server.app.mds import entries as mds_entries

AAGUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_an_entry_keeps_its_fields_trimmed_and_drops_blank_ones():
    entry, legal_header, payload = mds_entries.build_metadata_entry_components(
        {
            "timeOfLastStatusChange": " 2026-01-01 ",
            "attestationCertificateKeyIdentifiers": ["ab", "   ", 42],
            "aaid": " id#1 ",
            "aaguid": "   ",
            "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}, None],
            "metadataStatement": {"description": "demo", "icon": None},
        }
    )

    assert legal_header is None
    assert payload["timeOfLastStatusChange"] == "2026-01-01"
    assert payload["attestationCertificateKeyIdentifiers"] == ["ab"]
    assert payload["aaid"] == "id#1"
    assert "aaguid" not in payload
    assert payload["statusReports"] == [{"status": "NOT_FIDO_CERTIFIED"}]
    assert "icon" not in payload["metadataStatement"]
    assert entry.metadata_statement.description == "demo"


def test_an_entry_without_a_status_change_time_is_dated_today():
    _, _, payload = mds_entries.build_metadata_entry_components({"timeOfLastStatusChange": "   ", "metadataStatement": {}})

    assert payload["timeOfLastStatusChange"] == datetime.now(timezone.utc).date().isoformat()


def test_a_statement_given_without_its_entry_is_read_as_its_own_statement():
    _, legal_header, payload = mds_entries.build_metadata_entry_components(
        {"aaguid": AAGUID, "description": "flat", "legalHeader": " Legal ", "timeOfLastStatusChange": "2026-01-01"}
    )

    assert payload["aaguid"] == AAGUID
    assert legal_header == "Legal"
    assert payload["metadataStatement"]["description"] == "flat"
    # The statement is the upload itself, so it keeps the header as it was given.
    assert payload["metadataStatement"]["legalHeader"] == " Legal "
    # The entry's own fields are not the statement's.
    assert "aaguid" not in payload["metadataStatement"]
    assert "timeOfLastStatusChange" not in payload["metadataStatement"]


def test_an_upload_that_is_no_object_is_refused():
    with pytest.raises(TypeError, match="must be an object"):
        mds_entries.build_metadata_entry_components("not-a-mapping")
    with pytest.raises(TypeError, match="must be an object"):
        mds_entries.expand_metadata_entry_payloads("not-a-mapping")


def test_a_single_entry_upload_is_one_entry_and_a_blob_shaped_one_its_entries():
    single = {"metadataStatement": {"description": "single-entry"}}
    blob_shaped = {"legalHeader": "L", "entries": [{"metadataStatement": {}}, {"metadataStatement": {}, "legalHeader": "own"}]}

    assert mds_entries.expand_metadata_entry_payloads(single) == [single]
    assert [entry["legalHeader"] for entry in mds_entries.expand_metadata_entry_payloads(blob_shaped)] == ["L", "own"]


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        ({"entries": []}, "does not contain any entries"),
        ({"entries": ["not-a-mapping"]}, "Entry 1 is not a JSON object"),
        # What JSON never holds: only a direct call gives the reader one.
        ({"entries": [{"metadataStatement": object()}]}, "Entry 1 could not be cloned into a JSON object"),
    ],
)
def test_a_blob_shaped_upload_without_readable_entries_is_refused(raw, error):
    with pytest.raises(ValueError, match=error):
        mds_entries.expand_metadata_entry_payloads(raw)


@pytest.mark.parametrize(
    ("entry", "aaguid"),
    [
        (SimpleNamespace(aaguid=AAGUID), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        (SimpleNamespace(aaguid=None, metadata_statement={"aaguid": AAGUID.upper()}), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        (SimpleNamespace(aaguid=None, metadata_statement=None, metadataStatement="not-a-mapping"), None),
        (SimpleNamespace(aaguid=123, metadata_statement=None), None),
    ],
)
def test_an_entrys_aaguid_is_its_own_or_else_its_statements(entry, aaguid):
    assert mds_entries._extract_entry_aaguid(entry) == aaguid


BIOMETRIC_REPORT = {
    "certLevel": 1,
    "modality": "fingerprint_internal",
    "effectiveDate": "2026-02-01",
    "certificationDescriptor": "Fixture Fingerprint",
    "certificateNumber": "FIDO-BIO-001",
    "certificationPolicyVersion": "1.0.4",
    "certificationRequirementsVersion": "1.1",
}


def _entry_with_a_biometric_report() -> dict:
    return {
        "aaguid": "b10b10b1-0000-4000-8000-000000000001",
        "statusReports": [],
        "timeOfLastStatusChange": "2026-02-01",
        "biometricStatusReports": [BIOMETRIC_REPORT],
    }


def test_an_entry_with_a_biometric_report_as_mds3_writes_it_is_read_without_it():
    with pytest.raises(ValueError):
        MetadataBlobPayloadEntry.from_dict(_entry_with_a_biometric_report())

    entry = mds_entries.parse_entry(_entry_with_a_biometric_report())

    assert str(entry.aaguid) == "b10b10b1-0000-4000-8000-000000000001"
    assert entry.biometric_status_reports is None


def test_a_payload_whose_entry_has_a_biometric_report_is_read():
    payload = {"legalHeader": "", "no": 1, "nextUpdate": "2026-12-01", "entries": [_entry_with_a_biometric_report()]}

    assert len(mds_entries.parse_payload(payload).entries) == 1
    assert payload["entries"][0]["biometricStatusReports"] == [BIOMETRIC_REPORT]


def test_an_uploaded_blob_entry_keeps_every_entry_level_field():
    raw = {
        **_entry_with_a_biometric_report(),
        "rogueListURL": "https://upload.example/rogue.json",
        "rogueListHash": "00" * 32,
        "fixtureFutureField": {"kept": True},
        "legalHeader": "Upload Legal",
        "metadataStatement": {"description": "Uploaded"},
    }

    entry, legal_header, payload = mds_entries.build_metadata_entry_components(raw)

    assert payload["biometricStatusReports"] == [BIOMETRIC_REPORT]
    assert (payload["rogueListURL"], payload["rogueListHash"]) == ("https://upload.example/rogue.json", "00" * 32)
    assert payload["fixtureFutureField"] == {"kept": True}
    assert "legalHeader" not in payload and legal_header == "Upload Legal"
    assert entry.rogue_list_url == "https://upload.example/rogue.json"


def test_an_uploaded_statement_on_its_own_has_only_the_entry_fields_it_names():
    _entry, _legal_header, payload = mds_entries.build_metadata_entry_components(
        {"description": "Flat", "aaguid": "b10b10b1-0000-4000-8000-000000000001", "rogueListURL": "https://x.example"}
    )

    assert set(payload) == {"statusReports", "timeOfLastStatusChange", "aaguid", "metadataStatement"}
    assert payload["metadataStatement"]["rogueListURL"] == "https://x.example"
