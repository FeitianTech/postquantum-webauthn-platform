"""The MDS snapshot's file names and directory, in one Flask-free leaf."""
from __future__ import annotations

import json
import os
from pathlib import Path

from server.app import mds_snapshot_dir
from server.app.config import paths


def test_the_snapshot_is_seven_files_named_once():
    assert mds_snapshot_dir.SNAPSHOT_FILENAMES == (
        "blob.jwt",
        "fido-mds3.verified.json",
        "fido-mds3.verified.json.meta.json",
        "fido-mds3.explorer.json",
        "fido-mds3.explorer.json.meta.json",
        "fido-mds3.explorer.full.json",
        "fido-mds3.explorer.full.json.meta.json",
    )
    assert mds_snapshot_dir.BROWSER_FILENAMES == {"fido-mds3.explorer.full.json"}
    assert mds_snapshot_dir.PRIVATE_FILENAMES == {
        "blob.jwt",
        "fido-mds3.verified.json",
        "fido-mds3.explorer.json",
    }


def test_the_default_directory_is_in_the_instance_folder(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", raising=False)
    default = Path(paths.INSTANCE_ROOT) / "mds-snapshot"
    assert mds_snapshot_dir.DEFAULT_SNAPSHOT_DIR == default
    assert mds_snapshot_dir.snapshot_dir() == default
    assert mds_snapshot_dir.snapshot_file("blob.jwt") == default / "blob.jwt"


def test_the_setting_is_read_whenever_a_path_is_needed(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    assert mds_snapshot_dir.snapshot_dir() == tmp_path
    assert mds_snapshot_dir.snapshot_file("blob.jwt") == tmp_path / "blob.jwt"

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", "  ")
    assert mds_snapshot_dir.snapshot_dir() == mds_snapshot_dir.DEFAULT_SNAPSHOT_DIR


def test_a_relative_setting_is_made_absolute_as_given(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", "fixture/snapshot")
    assert mds_snapshot_dir.snapshot_dir() == tmp_path / "fixture" / "snapshot"

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", "~/mds")
    assert mds_snapshot_dir.snapshot_dir() == tmp_path / "mds"


def test_the_server_reads_the_snapshot_where_the_setting_says(monkeypatch, tmp_path, metadata_state, blob):
    payload = {"legalHeader": "L", "no": 3, "nextUpdate": "2099-01-01", "entries": []}
    (tmp_path / "fido-mds3.verified.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))

    assert blob._path(mds_snapshot_dir.VERIFIED) == os.fspath(tmp_path / "fido-mds3.verified.json")
    assert blob._load_verified_metadata_payload() == payload


def test_the_test_run_never_reads_the_checkout_snapshot():
    # tests/conftest.py points the run at an empty directory of its own.
    assert mds_snapshot_dir.snapshot_dir() != mds_snapshot_dir.DEFAULT_SNAPSHOT_DIR
    assert not any(mds_snapshot_dir.snapshot_file(name).exists() for name in mds_snapshot_dir.SNAPSHOT_FILENAMES)
    assert os.environ["FIDO_SERVER_MDS_FETCH_UPSTREAM"] == "0"
