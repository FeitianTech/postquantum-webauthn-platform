#!/usr/bin/env python3
"""Refresh the packaged FIDO MDS snapshot if the remote BLOB has changed."""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow imports from the repository root when executed as a standalone script.
    sys.path.insert(0, str(REPO_ROOT))

from fido2.mds3 import parse_blob

from server.server.config import (
    FIDO_METADATA_TRUST_ROOT_CERT,
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_PATH,
    MDS_METADATA_URL,
    MDS_METADATA_VERIFIED_PATH,
)
from server.server.metadata import format_last_modified_header, store_metadata_cache_entry


def _fetch_remote_blob() -> tuple[bytes, str | None, str | None]:
    request = urllib.request.Request(
        MDS_METADATA_URL,
        headers={"User-Agent": "webauthnlab-mds-updater"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - trusted host
        payload = response.read()
        headers = response.headers or {}
        last_modified = headers.get("Last-Modified")
        etag = headers.get("ETag")
    return payload, last_modified, etag


def _write_blob(blob: bytes) -> None:
    path = Path(MDS_METADATA_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def _write_verified_snapshot(blob: bytes) -> None:
    payload = parse_blob(blob, FIDO_METADATA_TRUST_ROOT_CERT)
    snapshot = dict(payload)
    target = Path(MDS_METADATA_VERIFIED_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_cache_state(last_modified: str | None, etag: str | None) -> None:
    store_metadata_cache_entry(
        last_modified_header=last_modified,
        last_modified_iso=format_last_modified_header(last_modified),
        etag=etag,
    )

    cache_path = Path(MDS_METADATA_CACHE_PATH)
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - unexpected format
            data = {}
        if "fetched_at" not in data or not data["fetched_at"]:
            data["fetched_at"] = datetime.now(timezone.utc).isoformat()
            cache_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    try:
        new_blob, last_modified, etag = _fetch_remote_blob()
    except Exception as exc:  # pragma: no cover - network failure propagates
        print(f"::error::Failed to download metadata BLOB: {exc}")
        return 1

    current_path = Path(MDS_METADATA_PATH)
    if current_path.exists() and current_path.read_bytes() == new_blob:
        print("Packaged metadata is already up to date; no changes made.")
        return 0

    _write_blob(new_blob)
    _write_verified_snapshot(new_blob)
    _write_cache_state(last_modified, etag)

    print("Packaged metadata snapshot refreshed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
