"""Utilities for interacting with Google Cloud Storage."""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Iterable, Optional

from google.api_core import exceptions as gcs_exceptions
from google.cloud import storage
from google.oauth2 import service_account

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

_CLIENT_LOCK = threading.Lock()
_CLIENT: Optional[storage.Client] = None
_BUCKET: Optional[storage.Bucket] = None


def _env_flag(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    normalised = raw.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True


def gcs_enabled() -> bool:
    """Return ``True`` when GCS access should be used for storage."""

    flag = _env_flag("FIDO_SERVER_GCS_ENABLED")
    if flag is not None:
        return flag

    # Default to disabled so that local development does not accidentally
    # interact with production buckets unless explicitly opted in.
    return False


def _build_client() -> storage.Client:
    credentials_path = os.environ.get("FIDO_SERVER_GCS_CREDENTIALS_FILE")
    credentials_json = os.environ.get("FIDO_SERVER_GCS_CREDENTIALS_JSON")
    project_override = os.environ.get("FIDO_SERVER_GCS_PROJECT")

    if credentials_path:
        credentials = service_account.Credentials.from_service_account_file(
            credentials_path
        )
        project_id = project_override or credentials.project_id
        return storage.Client(project=project_id, credentials=credentials)

    if credentials_json:
        info = json.loads(credentials_json)
        credentials = service_account.Credentials.from_service_account_info(info)
        project_id = project_override or info.get("project_id")
        return storage.Client(project=project_id, credentials=credentials)

    if project_override:
        return storage.Client(project=project_override)

    return storage.Client()


def _ensure_bucket() -> storage.Bucket:
    global _CLIENT, _BUCKET

    with _CLIENT_LOCK:
        if not gcs_enabled():
            raise RuntimeError("Google Cloud Storage access is disabled")

        if _BUCKET is not None:
            return _BUCKET

        bucket_name = os.environ.get("FIDO_SERVER_GCS_BUCKET")
        if not bucket_name:
            raise RuntimeError(
                "FIDO_SERVER_GCS_BUCKET must be configured to use cloud storage."
            )

        if _CLIENT is None:
            _CLIENT = _build_client()

        _BUCKET = _CLIENT.bucket(bucket_name)
        return _BUCKET


def ensure_ready(*, max_attempts: int = 3, retry_delay: float = 1.0) -> None:
    """Validate that the configured storage bucket is reachable."""

    last_error: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            bucket = _ensure_bucket()
            iterator = bucket.list_blobs(max_results=1)
            for _ in iterator:
                break
            return
        except Exception as exc:  # pragma: no cover - exercised in integration.
            last_error = exc
            if attempt >= max_attempts:
                break
            time.sleep(retry_delay)

    if last_error:
        raise last_error


def _normalise_prefix(prefix: Optional[str]) -> str:
    if not prefix:
        return ""
    cleaned = prefix.strip().strip("/")
    if not cleaned:
        return ""
    return cleaned + "/"


def build_blob_name(*components: str, prefix: Optional[str] = None) -> str:
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


def upload_bytes(blob_name: str, data: bytes, *, content_type: Optional[str] = None) -> None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    blob.upload_from_string(data, content_type=content_type)


def download_bytes(blob_name: str) -> Optional[bytes]:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    try:
        return blob.download_as_bytes()
    except gcs_exceptions.NotFound:
        return None


def delete_blob(blob_name: str, *, missing_ok: bool = True) -> None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    try:
        blob.delete()
    except gcs_exceptions.NotFound:
        if not missing_ok:
            raise


def list_blob_names(prefix: str) -> Iterable[str]:
    bucket = _ensure_bucket()
    iterator = bucket.list_blobs(prefix=prefix)
    for blob in iterator:
        yield blob.name


def blob_exists(blob_name: str) -> bool:
    bucket = _ensure_bucket()
    return bucket.blob(blob_name).exists()


def blob_updated_timestamp(blob_name: str) -> Optional[float]:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    try:
        blob.reload()
    except gcs_exceptions.NotFound:
        return None
    if blob.updated is None:
        return None
    return blob.updated.timestamp()
