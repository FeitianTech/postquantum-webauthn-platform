import copy
import json

import pytest

from server.app.mds import files as mds_files
from server.app.mds import snapshot as mds_snapshot
from server.app.mds.build import (
    build_bootstrap_snapshot,
    build_entry_id,
    build_explorer_entry,
    build_explorer_snapshot,
    normalise_aaguid_key,
)
from tests.app.metadata import mds_fixture


def _sample_payload():
    return {
        "legalHeader": "test header",
        "no": 240,
        "nextUpdate": "2099-01-01",
        "entries": [
            {
                "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "timeOfLastStatusChange": "2026-03-01",
                "statusReports": [
                    {
                        "status": "FIDO_CERTIFIED_L1",
                        "effectiveDate": "2026-03-01",
                        "certificationDescriptor": "Example",
                        "certificateNumber": "1234",
                    }
                ],
                "metadataStatement": {
                    "description": "Demo Authenticator",
                    "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "protocolFamily": "fido2",
                    "userVerificationDetails": [
                        [{"userVerificationMethod": "fingerprint_internal"}]
                    ],
                    "attachmentHint": ["wired"],
                    "keyProtection": ["hardware"],
                    "authenticationAlgorithms": ["secp256r1_ecdsa_sha256_raw"],
                    "attestationRootCertificates": ["CERTIFICATE"],
                    "attestationCertificateKeyIdentifiers": ["KEY-ID"],
                },
            }
        ],
    }


def test_build_entry_id_prefers_aaguid():
    payload = _sample_payload()["entries"][0]
    assert build_entry_id(payload) == "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_build_explorer_snapshot_is_deterministic():
    payload = _sample_payload()
    cache_info = {"fetched_at": "2026-04-01T00:00:00+00:00", "generated_at": "2026-04-01T00:00:00+00:00"}

    first = build_explorer_snapshot(copy.deepcopy(payload), cache_info)
    second = build_explorer_snapshot(copy.deepcopy(payload), cache_info)

    assert first == second
    assert first["meta"]["entryCount"] == 1
    assert first["entries"][0]["name"] == "Demo Authenticator"
    assert first["entries"][0]["protocol"] == "FIDO2"
    assert first["entries"][0]["source"] == "packaged"
    assert first["entries"][0]["trustAnchorStatus"] is True
    assert first["entries"][0]["isLightweightEntry"] is True


def test_build_explorer_entry_includes_detail_fields_when_requested():
    payload = _sample_payload()["entries"][0]
    snapshot_meta = {"generatedAt": "2026-04-01T00:00:00+00:00", "no": 240}

    entry = build_explorer_entry(
        payload,
        source="session",
        trust_anchor_status=False,
        snapshot_meta=snapshot_meta,
        include_detail=True,
        source_info={"storedFilename": "custom.json"},
    )

    assert entry["entryId"] == "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert entry["metadataStatement"]["description"] == "Demo Authenticator"
    assert entry["rawEntry"]["aaguid"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert entry["statusReports"][0]["status"] == "FIDO_CERTIFIED_L1"
    assert entry["source"] == "session"
    assert entry["sourceInfo"] == {"storedFilename": "custom.json"}
    assert entry["trustAnchorStatus"] is False
    assert entry["isLightweightEntry"] is False


def test_build_bootstrap_snapshot_keeps_detail_without_raw_entry():
    payload = _sample_payload()
    cache_info = {"generated_at": "2026-04-01T00:00:00+00:00"}

    snapshot = build_bootstrap_snapshot(payload, cache_info)
    entry = snapshot["entries"][0]

    assert entry["metadataStatement"]["description"] == "Demo Authenticator"
    assert entry["rawEntry"] is None
    assert entry["statusReports"][0]["status"] == "FIDO_CERTIFIED_L1"
    assert entry["attestationCertificates"] == ["CERTIFICATE"]
    assert entry["attestationKeyIdentifiers"] == ["KEY-ID"]
    assert "attestationRootCertificates" not in entry["metadataStatement"]
    assert "attestationCertificateKeyIdentifiers" not in entry["metadataStatement"]
    assert entry["isLightweightEntry"] is False


def test_normalise_aaguid_key_handles_hyphenated_values():
    assert normalise_aaguid_key("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_normalise_aaguid_key_returns_empty_for_invalid_values():
    assert normalise_aaguid_key(None) == ""
    assert normalise_aaguid_key("") == ""
    assert normalise_aaguid_key("not-a-guid") == ""


def test_build_explorer_entry_keeps_unparseable_status_date_text():
    payload = _sample_payload()["entries"][0]
    payload["timeOfLastStatusChange"] = "not-a-date"

    entry = build_explorer_entry(
        payload,
        source="session",
        trust_anchor_status=True,
        snapshot_meta={"generatedAt": "2026-04-01T00:00:00+00:00", "no": 240},
    )

    assert entry["timeOfLastStatusChange"] == "not-a-date"
    assert entry["dateTooltip"] == "not-a-date"
    assert entry["dateUpdated"] == "not-a-date"


def test_the_snapshots_files_are_written_sorted_and_the_full_one_compact():
    assert mds_snapshot._serialise_json({"b": 2, "a": 1}) == '{\n  "a": 1,\n  "b": 2\n}\n'
    assert mds_snapshot._serialise_compact_json({"b": 2, "a": "é"}) == '{"a":"é","b":2}\n'

    finalised = mds_snapshot._finalise_base_full_snapshot({"entries": [{"name": "a"}, {"name": "b"}], "meta": {"no": 5}})

    assert finalised["entries"] == [{"name": "a"}, {"name": "b"}]
    assert finalised["meta"] == {"no": 5, "entryCount": 2, "baseEntryCount": 2, "customEntryCount": 0, "hasCustomEntries": False}


def test_a_snapshots_seven_files_come_from_its_blob_payload_and_cache_state(monkeypatch):
    monkeypatch.setattr(mds_snapshot, "build_explorer_snapshot", lambda _verified, _cache: {"entries": [], "meta": {"kind": "e"}})
    monkeypatch.setattr(mds_snapshot, "build_bootstrap_snapshot", lambda _verified, _cache: {"entries": [{}], "meta": {}})

    files = mds_snapshot.snapshot_files(b"blob-data", {"entries": [], "no": 1}, {"a": 1})

    assert tuple(files) == mds_files.SNAPSHOT_FILENAMES
    assert files["blob.jwt"] == b"blob-data"
    assert files["fido-mds3.verified.json.meta.json"] == b'{\n  "a": 1\n}\n'
    assert json.loads(files["fido-mds3.explorer.json.meta.json"]) == {"kind": "e"}
    assert json.loads(files["fido-mds3.explorer.full.json"])["meta"]["baseEntryCount"] == 1


def test_a_snapshot_derived_from_its_blob_and_meta_is_the_one_the_updater_wrote(fixture_blob_root):
    written = {name: (mds_fixture.SNAPSHOT_DIR / name).read_bytes() for name in mds_files.SNAPSHOT_FILENAMES}

    derived = mds_snapshot.derive(written[mds_files.BLOB], written[mds_files.VERIFIED_META])

    assert derived == written


@pytest.mark.parametrize("meta", [b"[]", b"{}", b'{"fetched_at": 7}'])
def test_a_meta_that_names_no_fetch_time_is_refused(fixture_blob_root, meta):
    with pytest.raises(ValueError, match="names no time it was fetched"):
        mds_snapshot.derive((mds_fixture.SNAPSHOT_DIR / mds_files.BLOB).read_bytes(), meta)
