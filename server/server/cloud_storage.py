"""Local storage utilities that mirror the GCS blob storage interface.

This module provides the same API as Google Cloud Storage but uses a local
filesystem directory. This allows seamless migration from GCS by simply
copying the bucket contents to the local storage folder.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable, Optional

__all__ = [
    "blob_exists",
    "blob_updated_timestamp",
    "build_blob_name",
    "delete_blob",
    "download_bytes",
    "ensure_ready",
    "gcs_enabled",
    "list_blob_names",
    "upload_bytes",
]

# Base path for local storage - this mirrors the GCS bucket structure
# Users can copy their GCS bucket contents directly into this folder
_STORAGE_BASE_PATH = os.environ.get(
    "FIDO_SERVER_STORAGE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "storage")
)


def gcs_enabled() -> bool:
    """Return ``True`` - local storage is always enabled.

    This function is kept for API compatibility with code that checks
    whether storage is available.
    """
    return True


def ensure_ready(*, max_attempts: int = 3, retry_delay: float = 1.0) -> None:
    """Validate that the storage directory exists and is accessible."""
    storage_path = Path(_STORAGE_BASE_PATH)

    for attempt in range(1, max_attempts + 1):
        try:
            # Create the storage directory if it doesn't exist
            storage_path.mkdir(parents=True, exist_ok=True)

            # Verify we can write to it
            test_file = storage_path / ".write_test"
            test_file.write_bytes(b"test")
            test_file.unlink()
            return
        except Exception as exc:
            if attempt >= max_attempts:
                raise RuntimeError(
                    f"Unable to access storage directory {_STORAGE_BASE_PATH}: {exc}"
                ) from exc
            time.sleep(retry_delay)


def _normalise_prefix(prefix: Optional[str]) -> str:
    """Normalize a prefix string for path construction."""
    if not prefix:
        return ""
    cleaned = prefix.strip().strip("/")
    if not cleaned:
        return ""
    return cleaned + "/"


def build_blob_name(*components: str, prefix: Optional[str] = None) -> str:
    """Build a blob path from components, matching GCS blob naming."""
    base = _normalise_prefix(prefix)
    safe_components = []
    for component in components:
        if not component:
            continue
        safe_components.append(component.strip("/"))
    path = "/".join(filter(None, safe_components))
    if not path:
        raise ValueError("Invalid blob path components")
    return f"{base}{path}" if base else path


def _resolve_path(blob_name: str) -> Path:
    """Convert a blob name to a local filesystem path."""
    # Ensure the blob_name doesn't escape the storage directory
    normalized = os.path.normpath(blob_name)
    if normalized.startswith("..") or os.path.isabs(normalized):
        raise ValueError(f"Invalid blob name: {blob_name}")
    return Path(_STORAGE_BASE_PATH) / normalized


def upload_bytes(blob_name: str, data: bytes, *, content_type: Optional[str] = None) -> None:
    """Upload data to local storage, creating directories as needed."""
    file_path = _resolve_path(blob_name)

    # Create parent directories if they don't exist
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the data
    file_path.write_bytes(data)


def download_bytes(blob_name: str) -> Optional[bytes]:
    """Download data from local storage, returning None if not found."""
    file_path = _resolve_path(blob_name)

    try:
        return file_path.read_bytes()
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        return None


def delete_blob(blob_name: str, *, missing_ok: bool = True) -> None:
    """Delete a file from local storage."""
    file_path = _resolve_path(blob_name)

    try:
        file_path.unlink()
    except FileNotFoundError:
        if not missing_ok:
            raise


def list_blob_names(prefix: str) -> Iterable[str]:
    """List all blob names under a given prefix."""
    storage_path = Path(_STORAGE_BASE_PATH)
    prefix_path = storage_path / prefix.strip("/") if prefix else storage_path

    if not prefix_path.exists():
        return

    # Walk through all files under the prefix
    for file_path in prefix_path.rglob("*"):
        if file_path.is_file():
            # Return the path relative to storage base
            relative_path = file_path.relative_to(storage_path)
            yield str(relative_path)


def blob_exists(blob_name: str) -> bool:
    """Check if a blob exists in local storage."""
    file_path = _resolve_path(blob_name)
    return file_path.is_file()


def blob_updated_timestamp(blob_name: str) -> Optional[float]:
    """Get the last modified timestamp of a blob."""
    file_path = _resolve_path(blob_name)

    try:
        stat = file_path.stat()
        return stat.st_mtime
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        return None
