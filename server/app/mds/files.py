"""Where the FIDO MDS snapshot is: the seven files ``tools/update_mds_snapshot.py``
writes together, and the one directory they are read from and written to.

A leaf like ``mds.trust``: it imports nothing from the app, so the updater can use
it without building the Flask app. docs/MDS_SNAPSHOT.md has the whole picture.
"""
from __future__ import annotations

import gzip
import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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

# The .meta.json files, each describing the payload beside it and the verified
# snapshot. A set is written payloads first and metas last (``WRITE_ORDER``): a
# reader that finds the new metas finds the new payloads too.
META_FILENAMES = (VERIFIED_META, EXPLORER_META, EXPLORER_FULL_META)
WRITE_ORDER = tuple(name for name in SNAPSHOT_FILENAMES if name not in META_FILENAMES) + META_FILENAMES

# Browsers fetch this one as a versioned static asset, with its .gz sibling.
BROWSER_FILENAMES = frozenset({EXPLORER_FULL})
# Smaller than this, a browser file gets no .gz sibling.
MIN_GZIP_BYTES = 1024

# server/app/mds/files.py -> the checkout (or /app in the image). The
# instance folder holds what a deployment keeps beside its source, served by no
# route and ignored by git and Docker.
DEFAULT_SNAPSHOT_DIR = Path(__file__).resolve().parents[3] / "instance" / "mds-snapshot"


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


def write_file(path: Path, data: bytes) -> None:
    """Write one snapshot file whole: through a temporary file renamed over it, so
    a reader sees the old file or the new one, never part of one. A browser file's
    ``.gz`` sibling follows it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.partial")
    temporary.write_bytes(data)
    temporary.replace(path)
    if path.name in BROWSER_FILENAMES:
        write_gzip_sibling(path, data)


def parse_http_datetime(value: str | None) -> datetime | None:
    """An HTTP date (``Last-Modified``, ``Retry-After``) as an aware UTC time, or None."""

    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_last_modified(header: str | None) -> str | None:
    """A ``Last-Modified`` header as ISO 8601; the header as it is when it is not a date."""

    parsed = parse_http_datetime(header)
    if parsed is None:
        return header
    return parsed.isoformat()
