"""The MDS snapshot's file names and directory, in one Flask-free leaf."""
from __future__ import annotations

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


def test_the_default_directory_is_the_frontend_static_one():
    assert mds_snapshot_dir.DEFAULT_SNAPSHOT_DIR == paths._FRONTEND_STATIC_ROOT
    assert mds_snapshot_dir.snapshot_dir() == paths._FRONTEND_STATIC_ROOT
    assert mds_snapshot_dir.snapshot_file("blob.jwt") == paths._FRONTEND_STATIC_ROOT / "blob.jwt"
