import copy

from server.app.mds_snapshot import (
    build_entry_id,
    build_bootstrap_snapshot,
    build_explorer_entry,
    build_explorer_snapshot,
    normalise_aaguid_key,
)


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
