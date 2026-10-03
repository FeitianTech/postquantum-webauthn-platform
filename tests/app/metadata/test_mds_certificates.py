"""``mds.certificates``: what an entry's attestation roots say, for its explorer row."""
from __future__ import annotations

import base64
import io
import json

from server.app.mds import certificates as mds_certificates
from tests.app.characterization import material
from tests.app.metadata.upload_entries import minimal_entry

ROOT = material.certificate(material.ec_key("mds-unreadable-root").public_key(), common_name="Unreadable Root", serial=0x5B)
UNREADABLE = base64.b64encode(material.with_unreadable_subject(ROOT, "Unreadable Root")).decode()


def test_a_root_whose_subject_cryptography_will_not_read_gives_its_algorithm_and_no_name():
    algorithms, common_names = mds_certificates.summarise_attestation_certificates([UNREADABLE])

    assert algorithms == ["ED25519_SHA512"]
    assert common_names == []


def test_an_upload_with_such_a_root_is_listed_and_resolved(mds_fixture_snapshot, client, monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    entry = minimal_entry("Unreadable root")
    entry["metadataStatement"]["attestationRootCertificates"] = [UNREADABLE]

    upload = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(json.dumps(entry).encode()), "entry.json")},
        content_type="multipart/form-data",
    )

    assert upload.status_code == 200, upload.get_json()
    assert client.get("/api/mds/metadata/explorer/full").status_code == 200
    resolved = client.get(f"/api/mds/metadata/resolve?aaguid={entry['aaguid']}")
    assert resolved.status_code == 200
