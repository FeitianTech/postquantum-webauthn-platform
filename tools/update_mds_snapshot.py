#!/usr/bin/env python3
"""Refresh the packaged FIDO MDS snapshot if the remote BLOB has changed.

Downloads the BLOB, verifies it against the pinned trust root, and writes the
snapshot's seven files. ``--verify-only`` writes nothing; ``--publish`` (earlier
``--gcs-upload``) also publishes them to Cloud Storage as a snapshot set
(``server/app/mds_snapshot_sets.py``), which every server instance follows.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Imported after the sys.path bootstrap above.
from server.app import mds_snapshot_dir  # noqa: E402
from server.app.mds import blob as mds_blob  # noqa: E402
from server.app.mds.trust import FIDO_METADATA_TRUST_ROOT_CERT  # noqa: E402
from server.app.mds_snapshot import (  # noqa: E402
    build_bootstrap_snapshot,
    build_explorer_snapshot,
)

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = mds_snapshot_dir.BLOB

MDS_DOWNLOAD_MAX_ATTEMPTS = 5
MDS_DOWNLOAD_BACKOFF_BASE_SECONDS = 10
MDS_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
MDS_RETRY_AFTER_CAP_SECONDS = 120


def _path(name: str) -> Path:
    """A snapshot file, in the directory the server reads it from
    (``FIDO_SERVER_MDS_SNAPSHOT_DIR``, else ``instance/mds-snapshot``)."""

    return mds_snapshot_dir.snapshot_file(name)



def _parse_http_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def format_last_modified_header(header: str | None) -> str | None:
    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header
    return parsed.isoformat()


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


def _parse_retry_after(value: str | None) -> int | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        seconds = int(value)
    else:
        retry_at = _parse_http_datetime(value)
        if retry_at is None:
            return None
        seconds = int((retry_at - datetime.now(timezone.utc)).total_seconds())
    seconds = max(0, seconds)
    return min(seconds, MDS_RETRY_AFTER_CAP_SECONDS)


def _fetch_remote_blob_with_retry() -> tuple[bytes, str | None, str | None]:
    for attempt in range(1, MDS_DOWNLOAD_MAX_ATTEMPTS + 1):
        try:
            return _fetch_remote_blob()
        except urllib.error.HTTPError as exc:
            if exc.code not in MDS_RETRYABLE_STATUS_CODES or attempt == MDS_DOWNLOAD_MAX_ATTEMPTS:
                raise
            backoff = MDS_DOWNLOAD_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            if exc.code == 429:
                retry_after = _parse_retry_after(
                    exc.headers.get("Retry-After") if exc.headers else None
                )
                if retry_after is not None:
                    backoff = retry_after
            print(
                f"::warning::Retrying FIDO MDS download (attempt {attempt + 1}/"
                f"{MDS_DOWNLOAD_MAX_ATTEMPTS}) after {exc.code} response. "
                f"Waiting {backoff}s..."
            )
            time.sleep(backoff)
    raise RuntimeError("FIDO MDS download retries exhausted")  # pragma: no cover - defensive


def _write_blob(blob: bytes) -> None:
    path = _path(mds_snapshot_dir.BLOB)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def _serialise_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _serialise_compact_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n"


def _finalise_base_full_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    """Add the entry-count fields the explorer API reports for a session without uploads."""

    entries = snapshot.get("entries")
    entry_count = len(entries) if isinstance(entries, list) else 0
    meta = dict(snapshot.get("meta") or {})
    meta["entryCount"] = entry_count
    meta["baseEntryCount"] = entry_count
    meta["customEntryCount"] = 0
    meta["hasCustomEntries"] = False
    return {**snapshot, "meta": meta}


def _write_if_changed(path: Path, payload: str | bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        new_bytes = payload.encode("utf-8")
    else:
        new_bytes = payload

    if path.exists() and path.read_bytes() == new_bytes:
        return False

    mds_snapshot_dir.write_file(path, new_bytes)
    return True


def _load_existing_cache() -> dict[str, object]:
    if not _path(mds_snapshot_dir.VERIFIED_META).exists():
        return {}
    try:
        data = json.loads(_path(mds_snapshot_dir.VERIFIED_META).read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _build_cache_state(
    *,
    last_modified: str | None,
    etag: str | None,
    existing_cache: dict[str, object],
    blob_unchanged: bool,
    verified_snapshot: dict[str, object],
) -> dict[str, object]:
    now_iso = datetime.now(timezone.utc).isoformat()
    if blob_unchanged:
        fetched_at = (
            existing_cache.get("fetched_at")
            if isinstance(existing_cache.get("fetched_at"), str)
            else None
        ) or now_iso
        generated_at = (
            existing_cache.get("generated_at")
            if isinstance(existing_cache.get("generated_at"), str)
            else None
        ) or fetched_at
        resolved_last_modified = (
            existing_cache.get("last_modified")
            if isinstance(existing_cache.get("last_modified"), str)
            else last_modified
        )
        resolved_last_modified_iso = (
            existing_cache.get("last_modified_iso")
            if isinstance(existing_cache.get("last_modified_iso"), str)
            else format_last_modified_header(last_modified)
        )
        resolved_etag = (
            existing_cache.get("etag")
            if isinstance(existing_cache.get("etag"), str)
            else etag
        )
    else:
        fetched_at = now_iso
        generated_at = now_iso
        resolved_last_modified = last_modified
        resolved_last_modified_iso = format_last_modified_header(last_modified)
        resolved_etag = etag

    entries = verified_snapshot.get("entries")
    entry_count = len(entries) if isinstance(entries, list) else 0

    return {
        "last_modified": resolved_last_modified,
        "last_modified_iso": resolved_last_modified_iso,
        "etag": resolved_etag,
        "fetched_at": fetched_at,
        "generated_at": generated_at,
        "no": verified_snapshot.get("no"),
        "nextUpdate": verified_snapshot.get("nextUpdate"),
        "entryCount": entry_count,
    }


def snapshot_files(
    blob: bytes,
    verified_snapshot: dict[str, object],
    cache_state: dict[str, object],
) -> dict[str, bytes]:
    """The seven files of a snapshot, by name, as the server reads them: the BLOB,
    the verified payload and its cache state, and the explorer views built from
    them. Pure: tests/app/metadata/mds_fixture.py builds its fixture with it."""

    explorer_snapshot = build_explorer_snapshot(verified_snapshot, cache_state)
    # The full snapshot is what the explorer API returns for a session without
    # uploaded metadata; browsers load it as a cacheable static file.
    full_snapshot = _finalise_base_full_snapshot(
        build_bootstrap_snapshot(verified_snapshot, cache_state)
    )
    return {
        mds_snapshot_dir.BLOB: blob,
        mds_snapshot_dir.VERIFIED: _serialise_json(verified_snapshot).encode("utf-8"),
        mds_snapshot_dir.VERIFIED_META: _serialise_json(cache_state).encode("utf-8"),
        mds_snapshot_dir.EXPLORER: _serialise_json(explorer_snapshot).encode("utf-8"),
        mds_snapshot_dir.EXPLORER_META: _serialise_json(explorer_snapshot.get("meta", {})).encode("utf-8"),
        mds_snapshot_dir.EXPLORER_FULL: _serialise_compact_json(full_snapshot).encode("utf-8"),
        mds_snapshot_dir.EXPLORER_FULL_META: _serialise_json(full_snapshot.get("meta", {})).encode("utf-8"),
    }


def _build_verified_snapshot(
    blob: bytes, trust_root: bytes = FIDO_METADATA_TRUST_ROOT_CERT
) -> dict[str, object]:
    """The BLOB's payload as the BLOB has it, once ``mds.blob`` has checked its
    signature against the trust root and read it (a BLOB it cannot read fails
    here). Its own JSON rather than fido2's dataclasses, which drop every field
    they do not model: a status report's ``sunsetDate`` or
    ``certificationProfiles``, a statement's ``friendlyNames``."""

    return mds_blob.verify_blob(blob, trust_root)


def _publish_to_cloud_storage(files: dict[str, bytes]) -> int:
    """Publish the verified snapshot's files as a set in the bucket the server
    provisions from, and point to it (``server/app/mds_snapshot_sets.py``)."""

    from server.app import mds_snapshot_sets
    from server.app.storage import cloud

    if not cloud.gcs_enabled():
        print(
            "::error::Cloud Storage is disabled; set FIDO_SERVER_GCS_ENABLED=1 "
            "and FIDO_SERVER_GCS_BUCKET to publish the snapshot."
        )
        return 1

    try:
        # Losing the pointer to another publisher leaves the bucket at theirs, which
        # may be older than this one: read it again and publish over it if so.
        for _attempt in range(3):
            result = mds_snapshot_sets.publish(files)
            if result.outcome != "lost":
                break
    except Exception as exc:
        print(f"::error::Could not publish the snapshot to Cloud Storage: {exc}")
        return 1

    pointer = result.pointer or {}
    if result.outcome == "published":
        print(f"Published snapshot no. {pointer.get('no')} as {pointer.get('set')}.")
    elif result.outcome == "current":
        print(f"The bucket already has snapshot no. {pointer.get('no')}; nothing published.")
    else:
        print(f"::warning::Other publishers kept landing first (no. {pointer.get('no')}); nothing published.")
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    # --gcs-upload is the flag's earlier name.
    publish = "--publish" in arguments or "--gcs-upload" in arguments
    verify_only = "--verify-only" in arguments

    try:
        new_blob, last_modified, etag = _fetch_remote_blob_with_retry()
    except Exception as exc:
        print(f"::error::Failed to download metadata BLOB: {exc}")
        return 1

    current_path = _path(mds_snapshot_dir.BLOB)
    blob_unchanged = current_path.exists() and current_path.read_bytes() == new_blob

    try:
        verified_snapshot = _build_verified_snapshot(new_blob)
    except Exception as exc:
        print(f"::error::The metadata BLOB failed verification; nothing written: {exc}")
        return 1
    existing_cache = _load_existing_cache()
    cache_state = _build_cache_state(
        last_modified=last_modified,
        etag=etag,
        existing_cache=existing_cache,
        blob_unchanged=blob_unchanged,
        verified_snapshot=verified_snapshot,
    )
    files = snapshot_files(new_blob, verified_snapshot, cache_state)

    if verify_only:
        print(
            "Downloaded and verified the metadata BLOB "
            f"(no. {verified_snapshot.get('no')}); nothing written."
        )
        return 0

    # Each file whole, the payloads before the metas that describe them, so the
    # server reading the directory meanwhile never takes a new meta for an old file.
    changed = False
    for name in mds_snapshot_dir.WRITE_ORDER:
        written = _write_if_changed(_path(name), files[name])
        changed |= written
        if name in mds_snapshot_dir.BROWSER_FILENAMES and not written:
            # Rewritten every run, so a sibling from an earlier file never outlives it.
            mds_snapshot_dir.write_gzip_sibling(_path(name), files[name])

    if changed:
        print("Packaged metadata snapshot refreshed.")
    else:
        print("Packaged metadata is already up to date; no changes made.")

    if publish:
        return _publish_to_cloud_storage(files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
