"""``mds.certificates``: what an entry's attestation roots say, for its explorer row."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path

import pytest

from server.app.mds import build as mds_build
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


def test_the_certificate_summary_names_each_algorithm_once_and_skips_blank_common_names():
    certificates = [
        material.certificate(material.ec_key(label).public_key(), common_name=name, serial=serial)
        for label, name, serial in (("one", "CN-Valid", 1), ("two", "   ", 2), ("three", "cn-valid", 3))
    ]
    # As the BLOB holds them (base64), as bytes, and what holds no certificate at all.
    values = [base64.b64encode(certificates[0]).decode(), base64.b64encode(certificates[1]).decode(), certificates[2], "   ", 123]

    assert mds_certificates.summarise_attestation_certificates(values) == (["ED25519_SHA512"], ["CN-Valid"])


def test_a_certificate_value_is_its_bytes_or_their_base64():
    assert mds_certificates.decode_der_certificate(b"bytes") == b"bytes"
    assert mds_certificates.decode_der_certificate(memoryview(b"a")) == b"a"
    assert mds_certificates.decode_der_certificate("YQ") == b"a"
    assert mds_certificates.decode_der_certificate(123) is None
    assert mds_certificates.decode_der_certificate("   ") is None


_NEGATIVE_ROOTS = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "mds-negative-serial-roots.json").read_text()
)["certificates"]


@pytest.mark.parametrize("root", _NEGATIVE_ROOTS, ids=lambda root: root["description"])
@pytest.mark.parametrize("with_readable_root", [False, True])
def test_the_explorer_build_skips_a_real_root_a_future_loader_refuses(monkeypatch, root, with_readable_root):
    unreadable = base64.b64decode(root["derBase64"])
    assert hashlib.sha256(unreadable).hexdigest() == root["sha256"]
    assert root["serial"] < 0
    loader = mds_certificates.x509.load_der_x509_certificate
    attempted = []

    def load(der):
        attempted.append(der)
        if der == unreadable:
            raise ValueError("Certificate serial number must be positive")
        return loader(der)

    monkeypatch.setattr(mds_certificates.x509, "load_der_x509_certificate", load)
    roots = [root["derBase64"]]
    if with_readable_root:
        roots.append(base64.b64encode(ROOT).decode())
    entry = minimal_entry(root["description"])
    entry["metadataStatement"]["attestationRootCertificates"] = roots

    snapshot = mds_build.build_explorer_snapshot({"entries": [entry]}, include_detail=True)

    assert snapshot["meta"]["entryCount"] == 1
    shown = snapshot["entries"][0]
    assert shown["certificateAlgorithmInfoList"] == (["ED25519_SHA512"] if with_readable_root else [])
    assert shown["certificateCommonNameList"] == (["Unreadable Root"] if with_readable_root else [])
    assert shown["attestationCertificates"] == roots
    assert shown["rawEntry"]["metadataStatement"]["attestationRootCertificates"] == roots
    assert attempted == ([unreadable, ROOT] if with_readable_root else [unreadable])
