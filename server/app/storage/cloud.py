"""Utilities for interacting with Google Cloud Storage."""
from __future__ import annotations

import importlib
import os
import threading
from collections.abc import Iterable
from typing import Any

from ..env_flags import parse_env_flag

__all__ = [
    "blob_exists",
    "blob_updated_timestamp",
    "build_blob_name",
    "delete_blob",
    "download_bytes",
    "download_bytes_with_generation",
    "gcs_enabled",
    "list_blob_names",
    "normalise_blob_prefix",
    "upload_bytes",
    "upload_bytes_if_generation",
]

# The Google client libraries take most of the application's import time, so
# they are loaded on first use rather than when the server starts.
_LAZY_MODULES = {
    "gcs_exceptions": "google.api_core.exceptions",
    "auth_exceptions": "google.auth.exceptions",
    "storage": "google.cloud.storage",
}
_LAZY_IMPORT_LOCK = threading.Lock()

_CLIENT_LOCK = threading.Lock()
_CLIENT: Any | None = None
_BUCKET: Any | None = None

# How long one call keeps retrying what the client library calls transient (429,
# 408, 5xx, dropped connections, timeouts), with its own backoff.
_RETRY_TIMEOUT_SECONDS = 30.0
_RETRY: Any | None = None


def _lazy(name: str) -> Any:
    module = globals().get(name)
    if module is None:
        with _LAZY_IMPORT_LOCK:
            module = globals().get(name)
            if module is None:
                module = importlib.import_module(_LAZY_MODULES[name])
                globals()[name] = module
    return module


def _retry() -> Any:
    """google-cloud-storage's own ``DEFAULT_RETRY``, within ``_RETRY_TIMEOUT_SECONDS``."""

    global _RETRY
    if _RETRY is None:
        storage_retry = importlib.import_module("google.cloud.storage.retry")
        _RETRY = storage_retry.DEFAULT_RETRY.with_timeout(_RETRY_TIMEOUT_SECONDS)
    return _RETRY


def _not_found_error() -> type:
    return _lazy("gcs_exceptions").NotFound


def _env_flag(name: str) -> bool | None:
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
    # Application-default credentials: the service identity on Cloud Run.
    project = os.environ.get("FIDO_SERVER_GCS_PROJECT") or None
    return _lazy("storage").Client(project=project)


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


def normalise_blob_prefix(prefix: str | None) -> str:
    """Return ``prefix`` as an empty string or a single trailing-slash prefix."""

    if not prefix:
        return ""
    cleaned = prefix.strip().strip("/")
    if not cleaned:
        return ""
    return cleaned + "/"



def build_blob_name(*components: str, prefix: str | None = None) -> str:
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


def upload_bytes(blob_name: str, data: bytes, *, content_type: str | None = None) -> None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    # Retried although unconditional: it writes the same bytes each time.
    blob.upload_from_string(data, content_type=content_type, retry=_retry())


def download_bytes(blob_name: str) -> bytes | None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    try:
        return blob.download_as_bytes(retry=_retry())
    except _not_found_error():
        return None


def download_bytes_with_generation(
    blob_name: str, *, timeout: float | None = None, attempts: int | None = None
) -> tuple[bytes | None, int]:
    """The object's bytes and generation; ``(None, 0)`` when there is no object.

    ``timeout`` bounds each attempt (the client's own default is 60 s). With
    ``attempts=1`` the download is tried once, the client's retry off too: for a
    caller that would rather go without the object than keep a request waiting.
    """

    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    options: dict[str, Any] = {"retry": None if attempts == 1 else _retry()}
    if timeout is not None:
        options["timeout"] = timeout
    try:
        data = blob.download_as_bytes(**options)
    except _not_found_error():
        return None, 0
    # The download sets the generation from the response it read.
    return data, int(blob.generation or 0)


def upload_bytes_if_generation(
    blob_name: str, data: bytes, *, generation: int, content_type: str | None = None
) -> bool:
    """Upload only if the object is still at ``generation`` (0: there is none).

    Returns ``False``, having written nothing, when another writer got there
    first. Attempted once, with the client library's own retry off: a retried
    conditional upload whose first attempt did land would fail its own
    precondition and read as a lost race. A transient error raises instead.
    """

    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)
    try:
        blob.upload_from_string(
            data, content_type=content_type, if_generation_match=generation, retry=None
        )
    except _lazy("gcs_exceptions").PreconditionFailed:
        return False
    return True


def delete_blob(blob_name: str, *, missing_ok: bool = True) -> None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    try:
        blob.delete(retry=_retry())
    except _not_found_error():
        if not missing_ok:
            raise


def list_blob_names(prefix: str, *, delimiter: str | None = None) -> Iterable[str]:
    """The names of the objects under ``prefix``.

    With ``delimiter`` ("/"), only the objects directly under it: Cloud Storage
    leaves out every name with another delimiter after the prefix.
    """

    bucket = _ensure_bucket()

    options: dict[str, Any] = {"prefix": prefix, "retry": _retry()}
    if delimiter is not None:
        options["delimiter"] = delimiter
    names = [blob.name for blob in bucket.list_blobs(**options)]
    yield from names


def list_prefixes(prefix: str) -> list[str]:
    """The "folders" directly under ``prefix``: each ``<prefix><name>/`` that holds an object.

    Listed with a "/" delimiter, so Cloud Storage returns each folder once
    instead of every object in it. The client fills ``prefixes`` only as the
    listing's pages are read, so the listing is read to the end first.
    """

    bucket = _ensure_bucket()

    iterator = bucket.list_blobs(prefix=prefix, delimiter="/", retry=_retry())
    for _blob in iterator:
        pass
    return sorted(iterator.prefixes)


def blob_exists(blob_name: str) -> bool:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    return bool(blob.exists(retry=_retry()))


def blob_updated_timestamp(blob_name: str) -> float | None:
    bucket = _ensure_bucket()
    blob = bucket.blob(blob_name)

    try:
        blob.reload(retry=_retry())
    except _not_found_error():
        return None
    if blob.updated is None:
        return None
    return blob.updated.timestamp()
