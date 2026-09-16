"""Utilities for interacting with Google Cloud Storage."""
from __future__ import annotations

import importlib
import json
import os
import threading
import time
from typing import Any, Callable, Iterable, Optional, Tuple, TypeVar

from .env_flags import parse_env_flag

__all__ = [
    "blob_exists",
    "blob_updated_timestamp",
    "build_blob_name",
    "delete_blob",
    "download_bytes",
    "ensure_ready",
    "gcs_enabled",
    "list_blob_names",
    "normalise_blob_prefix",
    "upload_bytes",
]

# The Google client libraries take most of the application's import time, so
# they are loaded on first use rather than when the server starts.
_LAZY_MODULES = {
    "gcs_exceptions": "google.api_core.exceptions",
    "auth_exceptions": "google.auth.exceptions",
    "storage": "google.cloud.storage",
    "service_account": "google.oauth2.service_account",
}
_LAZY_IMPORT_LOCK = threading.Lock()

_CLIENT_LOCK = threading.Lock()
_CLIENT: Optional[Any] = None
_BUCKET: Optional[Any] = None

_RETRYABLE_EXCEPTIONS_CACHE: Optional[Tuple[type, ...]] = None
_DEFAULT_RETRY_ATTEMPTS = 3
_DEFAULT_RETRY_BASE_DELAY = 0.5

_T = TypeVar("_T")


def _lazy(name: str) -> Any:
    module = globals().get(name)
    if module is None:
        with _LAZY_IMPORT_LOCK:
            module = globals().get(name)
            if module is None:
                module = importlib.import_module(_LAZY_MODULES[name])
                globals()[name] = module
    return module


def __getattr__(name: str) -> Any:
    if name in _LAZY_MODULES:
        return _lazy(name)
    if name == "_RETRYABLE_EXCEPTIONS":
        return _retryable_exceptions()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _retryable_exceptions() -> Tuple[type, ...]:
    global _RETRYABLE_EXCEPTIONS_CACHE

    if _RETRYABLE_EXCEPTIONS_CACHE is None:
        gcs_exceptions = _lazy("gcs_exceptions")
        _RETRYABLE_EXCEPTIONS_CACHE = (
            gcs_exceptions.GoogleAPICallError,
            gcs_exceptions.RetryError,
            _lazy("auth_exceptions").RefreshError,
            OSError,
        )
    return _RETRYABLE_EXCEPTIONS_CACHE


def _not_found_error() -> type:
    return _lazy("gcs_exceptions").NotFound


def _env_flag(name: str) -> Optional[bool]:
    return parse_env_flag(name)


def gcs_enabled() -> bool:
    """Return ``True`` when GCS access should be used for storage."""

    flag = _env_flag("FIDO_SERVER_GCS_ENABLED")
    if flag is not None:
        return flag

    # Default to disabled so that local development does not accidentally
    # interact with production buckets unless explicitly opted in.
    return False


def _build_client() -> Any:
    storage = _lazy("storage")
    credentials_path = os.environ.get("FIDO_SERVER_GCS_CREDENTIALS_FILE")
    credentials_json = os.environ.get("FIDO_SERVER_GCS_CREDENTIALS_JSON")
    project_override = os.environ.get("FIDO_SERVER_GCS_PROJECT")

    if credentials_path:
        credentials = _lazy("service_account").Credentials.from_service_account_file(
            credentials_path
        )
        project_id = project_override or credentials.project_id
        return storage.Client(project=project_id, credentials=credentials)

    if credentials_json:
        info = json.loads(credentials_json)
        credentials = _lazy("service_account").Credentials.from_service_account_info(info)
        project_id = project_override or info.get("project_id")
        return storage.Client(project=project_id, credentials=credentials)

    if project_override:
        return storage.Client(project=project_override)

    return storage.Client()


def _ensure_bucket() -> Any:
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


def _with_retry(
    operation: Callable[[], _T],
    *,
    max_attempts: int = _DEFAULT_RETRY_ATTEMPTS,
    base_delay: float = _DEFAULT_RETRY_BASE_DELAY,
) -> _T:
    """Execute ``operation`` with retries for transient failures."""

    last_error: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except _not_found_error():
            raise
        except _retryable_exceptions() as exc:
            last_error = exc
            if attempt >= max_attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            time.sleep(delay)

    if last_error is not None:
        raise last_error

    raise RuntimeError("Retryable operation failed without raising an error")


def normalise_blob_prefix(prefix: Optional[str]) -> str:
    """Return ``prefix`` as an empty string or a single trailing-slash prefix."""

    if not prefix:
        return ""
    cleaned = prefix.strip().strip("/")
    if not cleaned:
        return ""
    return cleaned + "/"


# Historic private alias; kept so existing callers/tests keep working.
_normalise_prefix = normalise_blob_prefix


def build_blob_name(*components: str, prefix: Optional[str] = None) -> str:
    base = normalise_blob_prefix(prefix)
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

    def _upload() -> None:
        blob.upload_from_string(data, content_type=content_type)

    _with_retry(_upload)


def download_bytes(blob_name: str) -> Optional[bytes]:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    def _download() -> Optional[bytes]:
        try:
            return blob.download_as_bytes()
        except _not_found_error():
            return None

    return _with_retry(_download)


def delete_blob(blob_name: str, *, missing_ok: bool = True) -> None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    def _delete() -> None:
        try:
            blob.delete()
        except _not_found_error():
            if not missing_ok:
                raise

    _with_retry(_delete)


def list_blob_names(prefix: str) -> Iterable[str]:
    bucket = _ensure_bucket()

    def _list() -> Iterable[str]:
        iterator = bucket.list_blobs(prefix=prefix)
        return [blob.name for blob in iterator]

    for name in _with_retry(_list):
        yield name


def blob_exists(blob_name: str) -> bool:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    def _exists() -> bool:
        return blob.exists()

    return bool(_with_retry(_exists))


def blob_updated_timestamp(blob_name: str) -> Optional[float]:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    def _resolve_timestamp() -> Optional[float]:
        try:
            blob.reload()
        except _not_found_error():
            return None
        if blob.updated is None:
            return None
        return blob.updated.timestamp()

    return _with_retry(_resolve_timestamp)
