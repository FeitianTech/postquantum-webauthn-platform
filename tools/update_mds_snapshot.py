#!/usr/bin/env python3
"""Refresh the packaged FIDO MDS snapshot if the remote BLOB has changed."""

from __future__ import annotations

import base64
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

from fido2.mds3 import parse_blob
from server.app.mds_snapshot import build_bootstrap_snapshot, build_explorer_snapshot

FRONTEND_STATIC_DIR = REPO_ROOT / "frontend" / "static"

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "blob.jwt"

MDS_DOWNLOAD_MAX_ATTEMPTS = 5
MDS_DOWNLOAD_BACKOFF_BASE_SECONDS = 10
MDS_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
MDS_RETRY_AFTER_CAP_SECONDS = 120
MDS_METADATA_PATH = FRONTEND_STATIC_DIR / MDS_METADATA_FILENAME
MDS_METADATA_VERIFIED_PATH = FRONTEND_STATIC_DIR / "fido-mds3.verified.json"
MDS_METADATA_CACHE_PATH = Path(str(MDS_METADATA_VERIFIED_PATH) + ".meta.json")
MDS_EXPLORER_PATH = FRONTEND_STATIC_DIR / "fido-mds3.explorer.json"
MDS_EXPLORER_META_PATH = Path(str(MDS_EXPLORER_PATH) + ".meta.json")
MDS_BOOTSTRAP_JS_PATH = FRONTEND_STATIC_DIR / "fido-mds3.explorer.bootstrap.js"
MDS_BOOTSTRAP_META_PATH = FRONTEND_STATIC_DIR / "fido-mds3.explorer.bootstrap.meta.json"

FIDO_METADATA_TRUST_ROOT_B64 = (
    "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"
)
FIDO_METADATA_TRUST_ROOT_CERT = base64.b64decode(FIDO_METADATA_TRUST_ROOT_B64)


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


def store_metadata_cache_entry(
    *,
    last_modified_header: str | None,
    last_modified_iso: str | None,
    etag: str | None,
    fetched_at: str | None = None,
    generated_at: str | None = None,
    snapshot_no: int | None = None,
    next_update: str | None = None,
    entry_count: int | None = None,
) -> None:
    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at or datetime.now(timezone.utc).isoformat(),
        "generated_at": generated_at or fetched_at or datetime.now(timezone.utc).isoformat(),
        "no": snapshot_no,
        "nextUpdate": next_update,
        "entryCount": entry_count,
    }
    try:
        MDS_METADATA_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        MDS_METADATA_CACHE_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


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
    path = Path(MDS_METADATA_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def _serialise_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _serialise_bootstrap_script(snapshot: dict[str, object]) -> str:
    payload = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    return (
        "(function () {\n"
        f"  window.__INITIAL_MDS_SNAPSHOT__ = {payload};\n"
        "})();\n"
    )


def _write_if_changed(path: Path, payload: str | bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        new_bytes = payload.encode("utf-8")
    else:
        new_bytes = payload

    if path.exists() and path.read_bytes() == new_bytes:
        return False

    path.write_bytes(new_bytes)
    return True


def _load_existing_cache() -> dict[str, object]:
    if not MDS_METADATA_CACHE_PATH.exists():
        return {}
    try:
        data = json.loads(MDS_METADATA_CACHE_PATH.read_text(encoding="utf-8"))
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


def _build_verified_snapshot(blob: bytes) -> dict[str, object]:
    payload = parse_blob(blob, FIDO_METADATA_TRUST_ROOT_CERT)
    return dict(payload)


def _write_cache_state(cache_state: dict[str, object]) -> bool:
    return _write_if_changed(MDS_METADATA_CACHE_PATH, _serialise_json(cache_state))


def main() -> int:
    try:
        new_blob, last_modified, etag = _fetch_remote_blob_with_retry()
    except Exception as exc:  # pragma: no cover - network failure propagates
        print(f"::error::Failed to download metadata BLOB: {exc}")
        return 1

    current_path = Path(MDS_METADATA_PATH)
    blob_unchanged = current_path.exists() and current_path.read_bytes() == new_blob

    verified_snapshot = _build_verified_snapshot(new_blob)
    existing_cache = _load_existing_cache()
    cache_state = _build_cache_state(
        last_modified=last_modified,
        etag=etag,
        existing_cache=existing_cache,
        blob_unchanged=blob_unchanged,
        verified_snapshot=verified_snapshot,
    )
    explorer_snapshot = build_explorer_snapshot(verified_snapshot, cache_state)
    explorer_meta = explorer_snapshot.get("meta", {})
    bootstrap_snapshot = build_bootstrap_snapshot(verified_snapshot, cache_state)
    bootstrap_meta = bootstrap_snapshot.get("meta", {})

    changed = False
    changed |= _write_if_changed(MDS_METADATA_PATH, new_blob)
    changed |= _write_if_changed(MDS_METADATA_VERIFIED_PATH, _serialise_json(verified_snapshot))
    changed |= _write_cache_state(cache_state)
    changed |= _write_if_changed(MDS_EXPLORER_PATH, _serialise_json(explorer_snapshot))
    changed |= _write_if_changed(MDS_EXPLORER_META_PATH, _serialise_json(explorer_meta))
    changed |= _write_if_changed(MDS_BOOTSTRAP_JS_PATH, _serialise_bootstrap_script(bootstrap_snapshot))
    changed |= _write_if_changed(MDS_BOOTSTRAP_META_PATH, _serialise_json(bootstrap_meta))

    if changed:
        print("Packaged metadata snapshot refreshed.")
    else:
        print("Packaged metadata is already up to date; no changes made.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
