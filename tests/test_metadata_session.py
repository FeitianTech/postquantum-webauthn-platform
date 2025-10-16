import json
from datetime import datetime, timezone

from flask import session

from server.server import metadata
from server.server.config import app


def _reset_metadata_state():
    metadata._base_metadata_cache = None
    metadata._base_metadata_mtime = None
    metadata._base_metadata_trust_verified = None
    metadata._base_metadata_entry_ids = set()
    metadata._base_verifier_cache = None
    metadata._base_verifier_mtime = None
    metadata._session_metadata_entry_ids = set()


def _sample_metadata_payload():
    today = datetime.now(timezone.utc).date().isoformat()
    return {
        "legalHeader": "Test header",
        "no": 1,
        "nextUpdate": today,
        "entries": [
            {
                "aaguid": "00112233445566778899AABBCCDDEEFF",
                "metadataStatement": {
                    "description": "Test",
                    "authenticatorVersion": 0,
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
                "statusReports": [],
                "timeOfLastStatusChange": today,
            }
        ],
    }


def test_load_base_metadata_uses_verified_blob(tmp_path, monkeypatch):
    _reset_metadata_state()

    payload = _sample_metadata_payload()
    metadata_path = tmp_path / "fido-mds3.verified.json"
    metadata_path.write_text(json.dumps(payload))
    jws_path = tmp_path / "fido-mds3.verified.json.jws"
    jws_path.write_bytes(b"dummy-blob")

    def fake_parse(blob: bytes, trust_root: bytes):
        assert blob == b"dummy-blob"
        assert trust_root == metadata.FIDO_METADATA_TRUST_ROOT_CERT
        return metadata.MetadataBlobPayload.from_dict(payload)

    monkeypatch.setattr(metadata, "parse_blob", fake_parse)
    monkeypatch.setattr(metadata, "MDS_METADATA_PATH", str(metadata_path))
    monkeypatch.setattr(metadata, "MDS_METADATA_JWS_PATH", str(jws_path))

    loaded, _ = metadata._load_base_metadata()
    assert loaded is not None
    assert metadata._base_metadata_trust_verified is True

    entry = loaded.entries[0]
    assert metadata.metadata_entry_trust_anchor_status(entry) is True


def test_metadata_without_verified_blob_not_trusted(tmp_path, monkeypatch):
    _reset_metadata_state()

    payload = _sample_metadata_payload()
    metadata_path = tmp_path / "fido-mds3.verified.json"
    metadata_path.write_text(json.dumps(payload))

    monkeypatch.setattr(metadata, "MDS_METADATA_PATH", str(metadata_path))
    monkeypatch.setattr(
        metadata, "MDS_METADATA_JWS_PATH", str(tmp_path / "fido-mds3.verified.json.jws")
    )

    loaded, _ = metadata._load_base_metadata()
    assert loaded is not None
    assert metadata._base_metadata_trust_verified is False

    entry = loaded.entries[0]
    assert metadata.metadata_entry_trust_anchor_status(entry) is False


def test_custom_metadata_stored_in_session(monkeypatch):
    _reset_metadata_state()

    payload = _sample_metadata_payload()["entries"][0]

    with app.test_request_context("/"):
        session.pop(metadata._SESSION_METADATA_ITEMS_KEY, None)
        metadata.ensure_metadata_session_id()

        item = metadata.save_session_metadata_item(payload, original_filename="custom.json")
        assert item.original_filename == "custom.json"
        assert metadata.metadata_entry_trust_anchor_status(item.entry) is False

        items = metadata.list_session_metadata_items()
        assert items and items[0].filename == item.filename

        stored = session.get(metadata._SESSION_METADATA_ITEMS_KEY)
        assert isinstance(stored, list)
        assert stored[0]["stored_filename"] == item.filename

        assert metadata.delete_session_metadata_item(item.filename) is True
        assert metadata.list_session_metadata_items() == []
