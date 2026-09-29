"""Where the FIDO MDS snapshot is: the seven files ``tools/update_mds_snapshot.py``
writes together, and the one directory they are read from and written to.

A leaf like ``mds_trust``: it imports nothing from the app, so the updater can use
it without building the Flask app. docs/MDS_SNAPSHOT.md has the whole picture.
"""
from __future__ import annotations

import gzip
import os
from pathlib import Path

# Where the snapshot is, when not the default below. Read whenever a path is needed
# (not at import), so the updater, the provisioning at a cold start and every
# request agree, and a test or a browser run can serve a fixture of its own.
SNAPSHOT_DIR_ENV = "FIDO_SERVER_MDS_SNAPSHOT_DIR"

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
# Smaller than this, a browser file gets no .gz sibling.
MIN_GZIP_BYTES = 1024

# Large source files the server reads and browsers never request.
PRIVATE_FILENAMES = frozenset({BLOB, VERIFIED, EXPLORER})

# server/app/mds_snapshot_dir.py -> the checkout (or /app in the image). The
# instance folder holds what a deployment keeps beside its source, served by no
# route and ignored by git and Docker.
DEFAULT_SNAPSHOT_DIR = Path(__file__).resolve().parents[2] / "instance" / "mds-snapshot"


def snapshot_dir() -> Path:
    """The directory the snapshot is read from and written to."""

    configured = (os.environ.get(SNAPSHOT_DIR_ENV) or "").strip()
    # absolute(), not resolve(): a path compared as text stays as it was given.
    return Path(configured).expanduser().absolute() if configured else DEFAULT_SNAPSHOT_DIR


def snapshot_file(name: str) -> Path:
    return snapshot_dir() / name


def write_gzip_sibling(path: Path, data: bytes) -> None:
    """Write the ``.gz`` sibling browsers are sent for ``path``, which holds ``data``.

    Kept only when it is smaller than the file, and written through a temporary
    file; otherwise a sibling left from an earlier file is removed, so gzip clients
    are never sent an older snapshot than the file.
    """

    sibling = path.with_name(f"{path.name}.gz")
    compressed = gzip.compress(data, compresslevel=9, mtime=0) if len(data) >= MIN_GZIP_BYTES else data
    if len(compressed) >= len(data):
        sibling.unlink(missing_ok=True)
        return
    temporary = path.with_name(f"{path.name}.gz.partial")
    temporary.write_bytes(compressed)
    temporary.replace(sibling)
