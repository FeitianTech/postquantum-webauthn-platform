"""Metadata cache and HTTP header helpers."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from fido2.mds3 import MetadataBlobPayload

from ...config import (
    MDS_EXPLORER_FULL_PATH,
    MDS_EXPLORER_PATH,
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_VERIFIED_PATH,
    app,
)
from ...mds_snapshot import build_bootstrap_snapshot, build_explorer_snapshot
from . import state as _state


class MetadataDownloadError(Exception):
    """Raised when the FIDO MDS metadata cannot be downloaded."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def _parse_http_datetime(value: str | None) -> datetime | None:
    """Best-effort parsing of an HTTP date header into an aware datetime."""

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


def _format_last_modified(header: str | None) -> str | None:
    """Convert an HTTP Last-Modified header to an ISO formatted string."""

    if not header:
        return None

    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header

    return parsed.isoformat()


def format_last_modified_header(header: str | None) -> str | None:
    """Public helper for converting HTTP Last-Modified headers to ISO format."""

    return _format_last_modified(header)


def _clean_metadata_cache_value(value: Any) -> str | None:
    """Return a trimmed string value from cached metadata state if present."""

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def load_metadata_cache_entry() -> dict[str, str | None]:
    """Load cached metadata headers used for conditional download requests."""

    try:
        with open(MDS_METADATA_CACHE_PATH, "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(cached, dict):
        return {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = _format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _store_metadata_cache_entry(
    *,
    last_modified_header: str | None,
    last_modified_iso: str | None,
    etag: str | None,
) -> None:
    """Persist cached metadata download headers for future requests."""

    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        os.makedirs(os.path.dirname(MDS_METADATA_CACHE_PATH), exist_ok=True)
        with open(MDS_METADATA_CACHE_PATH, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, indent=2, sort_keys=True)
            cache_file.write("\n")
    except OSError:
        pass


def store_metadata_cache_entry(
    *,
    last_modified_header: str | None,
    last_modified_iso: str | None,
    etag: str | None,
) -> None:
    """Persist cached metadata headers for the packaged snapshot."""

    _store_metadata_cache_entry(
        last_modified_header=last_modified_header,
        last_modified_iso=last_modified_iso,
        etag=etag,
    )


def download_metadata_blob(
    source_url: str | None = None,
    destination: str | None = None,
) -> tuple[bool, int, str | None]:
    """Fetch the FIDO MDS metadata BLOB and store it locally.

    Runtime downloads are no longer supported. The packaged snapshot is
    refreshed exclusively by the CI workflow that invokes
    ``tools/update_mds_snapshot.py``.
    """

    _ = (source_url, destination)

    raise RuntimeError(
        "Runtime metadata downloads are disabled; use the CI snapshot updater instead."
    )


def load_cached_metadata_snapshot() -> bool:
    """Warm in-memory caches from the stored MDS metadata when available."""

    metadata, _ = _load_base_metadata()
    return metadata is not None


def _load_base_metadata() -> tuple[MetadataBlobPayload | None, float | None]:
    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _state._base_metadata_cache is not None
        and _state._base_metadata_source == "verified"
        and _state._base_metadata_mtime == verified_mtime
    ):
        return _state._base_metadata_cache, verified_mtime

    # Concurrent requests on a cold instance wait for a single parse of the
    # multi-megabyte snapshot instead of each loading their own copy.
    with _state._base_metadata_lock:
        if (
            _state._base_metadata_cache is not None
            and _state._base_metadata_source == "verified"
            and _state._base_metadata_mtime == verified_mtime
        ):
            return _state._base_metadata_cache, verified_mtime

        metadata, fallback_mtime = _load_verified_metadata_fallback()

        # Entry ids are published before the trust flag so a concurrent reader
        # can only ever observe "not yet trusted", never a stale trusted state.
        if metadata is not None:
            _state._base_metadata_entry_ids = {id(entry) for entry in metadata.entries}
            _state._base_metadata_trust_verified = True
            _state._base_metadata_source = "verified"
        else:
            _state._base_metadata_trust_verified = None
            _state._base_metadata_entry_ids = set()
            _state._base_metadata_source = None

        _state._base_metadata_cache = metadata
        _state._base_metadata_mtime = fallback_mtime
        return metadata, fallback_mtime


def _load_verified_metadata_fallback() -> tuple[MetadataBlobPayload | None, float | None]:
    """Load the bundled verified metadata snapshot shipped with the application."""

    try:
        fallback_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        fallback_mtime = None

    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except FileNotFoundError:
        return None, fallback_mtime
    except (OSError, json.JSONDecodeError) as exc:
        app.logger.warning(
            "Unable to load verified metadata fallback %s: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime

    try:
        return MetadataBlobPayload.from_dict(payload), fallback_mtime
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.warning(
            "Verified metadata fallback %s is invalid: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime


def _load_verified_metadata_payload() -> dict[str, Any] | None:
    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def _load_packaged_explorer_meta(snapshot_path: str | None = None) -> dict[str, Any] | None:
    """Return a packaged snapshot's meta when it describes the verified snapshot.

    The snapshot tool writes every packaged file and its meta in one run, so
    matching ``no``, ``etag`` and generation time mean the packaged snapshot is
    current. File mtimes cannot be used for this: checkouts and image builds do
    not preserve their relative order. Defaults to the explorer snapshot.
    """

    path = snapshot_path or MDS_EXPLORER_PATH
    try:
        with open(path + ".meta.json", "r", encoding="utf-8") as handle:
            explorer_meta = json.load(handle)
        with open(MDS_METADATA_VERIFIED_PATH + ".meta.json", "r", encoding="utf-8") as handle:
            verified_meta = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(explorer_meta, dict) or not isinstance(verified_meta, dict):
        return None

    explorer_key = (
        explorer_meta.get("no"),
        explorer_meta.get("etag"),
        explorer_meta.get("generatedAt"),
    )
    verified_key = (
        verified_meta.get("no"),
        verified_meta.get("etag"),
        verified_meta.get("generated_at"),
    )
    if None in explorer_key or explorer_key != verified_key:
        return None
    return explorer_meta


def _load_base_explorer_snapshot() -> tuple[dict[str, Any] | None, tuple[float | None, float | None] | None]:
    try:
        explorer_mtime = os.path.getmtime(MDS_EXPLORER_PATH)
    except OSError:
        explorer_mtime = None

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    cache_marker = (explorer_mtime, verified_mtime)
    if (
        _state._base_explorer_snapshot_cache is not None
        and _state._base_explorer_snapshot_mtime == cache_marker
    ):
        return _state._base_explorer_snapshot_cache, cache_marker

    with _state._base_explorer_snapshot_lock:
        if (
            _state._base_explorer_snapshot_cache is not None
            and _state._base_explorer_snapshot_mtime == cache_marker
        ):
            return _state._base_explorer_snapshot_cache, cache_marker

        snapshot: dict[str, Any] | None = None

        packaged_is_current = explorer_mtime is not None and (
            verified_mtime is None
            or explorer_mtime >= verified_mtime
            or _load_packaged_explorer_meta() is not None
        )
        if packaged_is_current:
            try:
                with open(MDS_EXPLORER_PATH, "r", encoding="utf-8") as explorer_file:
                    loaded = json.load(explorer_file)
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict):
                snapshot = loaded

        if snapshot is None:
            payload = _load_verified_metadata_payload()
            if payload is not None:
                snapshot = build_explorer_snapshot(payload, load_metadata_cache_entry())

        _state._base_explorer_snapshot_cache = snapshot
        _state._base_explorer_snapshot_mtime = cache_marker
        return snapshot, cache_marker


def _load_base_full_snapshot() -> tuple[dict[str, Any] | None, float | None]:
    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _state._base_full_snapshot_cache is not None
        and _state._base_full_snapshot_mtime == verified_mtime
    ):
        return _state._base_full_snapshot_cache, verified_mtime

    with _state._base_full_snapshot_lock:
        if (
            _state._base_full_snapshot_cache is not None
            and _state._base_full_snapshot_mtime == verified_mtime
        ):
            return _state._base_full_snapshot_cache, verified_mtime

        snapshot: dict[str, Any] | None = None

        # The packaged full snapshot is built by the same code as the fallback
        # below; loading it avoids re-parsing every attestation certificate.
        if _load_packaged_explorer_meta(MDS_EXPLORER_FULL_PATH) is not None:
            try:
                with open(MDS_EXPLORER_FULL_PATH, "r", encoding="utf-8") as full_file:
                    loaded = json.load(full_file)
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
                snapshot = loaded

        if snapshot is None:
            payload = _load_verified_metadata_payload()
            if payload is not None:
                snapshot = build_bootstrap_snapshot(payload, load_metadata_cache_entry())

        _state._base_full_snapshot_cache = snapshot
        _state._base_full_snapshot_mtime = verified_mtime
        return snapshot, verified_mtime


def load_packaged_explorer_summary() -> dict[str, Any]:
    # The summary is only the snapshot's meta block, which the packaged meta
    # file already holds; avoid parsing the multi-megabyte snapshot for it.
    if _state._base_explorer_snapshot_cache is None:
        packaged_meta = _load_packaged_explorer_meta()
        if packaged_meta is not None:
            return dict(packaged_meta)

    snapshot, _ = _load_base_explorer_snapshot()
    if snapshot and isinstance(snapshot.get("meta"), Mapping):
        return dict(snapshot["meta"])

    payload = _load_verified_metadata_payload()
    if payload is None:
        return {}

    return build_explorer_snapshot(payload, load_metadata_cache_entry()).get("meta", {})
