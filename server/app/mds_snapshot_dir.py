"""Where the FIDO MDS snapshot is: the seven files ``tools/update_mds_snapshot.py``
writes together, and the one directory they are read from and written to.

A leaf like ``mds_trust``: it imports nothing from the app, so the updater can use
it without building the Flask app. docs/MDS_SNAPSHOT.md has the whole picture.
"""
from __future__ import annotations

from pathlib import Path

BLOB = "blob.jwt"
VERIFIED = "fido-mds3.verified.json"
VERIFIED_META = VERIFIED + ".meta.json"
EXPLORER = "fido-mds3.explorer.json"
EXPLORER_META = EXPLORER + ".meta.json"
EXPLORER_FULL = "fido-mds3.explorer.full.json"
EXPLORER_FULL_META = EXPLORER_FULL + ".meta.json"

# Every file the updater writes. The payloads and their .meta.json companions are
# generated together and describe each other, so they are provisioned together.
SNAPSHOT_FILENAMES = (
    BLOB,
    VERIFIED,
    VERIFIED_META,
    EXPLORER,
    EXPLORER_META,
    EXPLORER_FULL,
    EXPLORER_FULL_META,
)

# Browsers fetch this one as a versioned static asset, with its .gz sibling.
BROWSER_FILENAMES = frozenset({EXPLORER_FULL})

# Large source files the server reads and browsers never request.
PRIVATE_FILENAMES = frozenset({BLOB, VERIFIED, EXPLORER})

# server/app/mds_snapshot_dir.py -> the checkout (or /app in the image).
DEFAULT_SNAPSHOT_DIR = Path(__file__).resolve().parents[2] / "frontend" / "static"


def snapshot_dir() -> Path:
    """The directory the snapshot is read from and written to."""

    return DEFAULT_SNAPSHOT_DIR


def snapshot_file(name: str) -> Path:
    return snapshot_dir() / name
