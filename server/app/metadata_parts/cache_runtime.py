"""Metadata cache and HTTP header helpers."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from ..config import MDS_METADATA_CACHE_PATH


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
