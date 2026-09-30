"""The GitHub mirror: registrations and uploaded metadata, copied to the credential log repository.

``record_registration_event`` writes one JSON file per registration under
``logs/<aaguid>/`` (on Cloud Run inline, otherwise on a thread), and
``maybe_store_uploaded_metadata_file`` copies a visitor's uploaded metadata under
``metadata/`` unless an identical file is there. Nothing is sent without
``GITHUB_TOKEN``, and ``ENABLE_GITHUB_LOGGING=0`` turns the mirror off.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request
from zoneinfo import ZoneInfo

import cbor2

from .. import encoding
from ..encoding import encode_base64, encode_base64url
from ..env_flags import parse_env_flag
from ..json_values import make_json_safe

__all__ = [
    "RegistrationEvent",
    "credential_log_repository",
    "git_blob_sha",
    "github_list_directory",
    "github_upload_file",
    "github_upload_json",
    "is_logging_enabled",
    "maybe_store_uploaded_metadata_file",
    "random_shortid",
    "record_registration_event",
    "safe_cbor_decode",
    "to_b64url",
    "uuid_bytes_to_str",
]

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_DEFAULT_REPO_OWNER = "rainzhang05"
_DEFAULT_REPO_NAME = "CredentialLogs"


def is_logging_enabled() -> bool:
    """Return ``True`` when GitHub logging should be active."""

    explicit = parse_env_flag("ENABLE_GITHUB_LOGGING")
    if explicit is not None:
        return explicit

    # On by default, on Cloud Run and locally alike; ENABLE_GITHUB_LOGGING=false
    # turns it off.
    return True


def credential_log_repository() -> tuple[str, str]:
    """Return the owner/name pair for the credential log repository."""

    owner = os.environ.get("GITHUB_LOG_REPO_OWNER", _DEFAULT_REPO_OWNER).strip()
    name = os.environ.get("GITHUB_LOG_REPO_NAME", _DEFAULT_REPO_NAME).strip()

    if not owner:
        owner = _DEFAULT_REPO_OWNER
    if not name:
        name = _DEFAULT_REPO_NAME

    return owner, name


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        owner, name = credential_log_repository()
        raise RuntimeError(
            f"GITHUB_TOKEN environment variable is required for credential logging to {owner}/{name}"
        )
    return token


def _api_url(path: str) -> str:
    path = path.lstrip("/")
    owner, name = credential_log_repository()
    return f"{_API_BASE}/repos/{owner}/{name}/{path}"


_DEFAULT_HTTP_TIMEOUT_SECONDS = 4.0


def _http_timeout() -> float:
    """Return the per-request GitHub timeout so a slow API cannot stall requests."""

    raw = os.environ.get("GITHUB_HTTP_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else _DEFAULT_HTTP_TIMEOUT_SECONDS
    except ValueError:
        return _DEFAULT_HTTP_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_HTTP_TIMEOUT_SECONDS


def _request(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[int, bytes]:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib_request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("User-Agent", "postquantum-webauthn-logger")
    if body is not None:
        req.add_header("Content-Type", "application/json")

    timeout = _http_timeout()
    for attempt in range(2):
        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), resp.read()
        except urllib_error.HTTPError as exc:
            if 500 <= exc.code < 600 and attempt == 0:
                time.sleep(1)
                continue
            raise
        except urllib_error.URLError as exc:
            # Retrying a timeout would double the worst-case request latency.
            if attempt == 0 and not isinstance(exc.reason, TimeoutError):
                time.sleep(1)
                continue
            raise
    raise RuntimeError("GitHub request failed after retries")


def _encode_content(data: bytes) -> str:
    return encode_base64(data)


def git_blob_sha(data: bytes) -> str:
    """Return the git blob SHA1 for ``data``."""

    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def github_upload_json(path: str, obj: dict[str, Any]) -> None:
    """Create a JSON file at ``path`` in the credential log repository."""

    serialised = json.dumps(obj, ensure_ascii=False, indent=2)
    content = _encode_content(serialised.encode("utf-8"))

    filename = os.path.basename(path)
    folder = os.path.basename(os.path.dirname(path)) or "unknown"

    body: dict[str, Any] = {
        "message": f"add: {filename} (AAGUID={folder})",
        "content": content,
    }

    url = _api_url(f"contents/{path}")
    _request("PUT", url, body)


def github_upload_file(path: str, data: bytes, message: str, sha: str | None = None) -> None:
    """Create or replace a file at ``path`` with ``data`` in the log repository."""

    body: dict[str, Any] = {
        "message": message,
        "content": _encode_content(data),
    }
    if sha:
        body["sha"] = sha

    url = _api_url(f"contents/{path}")
    _request("PUT", url, body)


def github_list_directory(path: str) -> list[dict[str, Any]]:
    """Return the metadata for files within ``path`` in the log repository."""

    url = _api_url(f"contents/{path}")
    try:
        _, body = _request("GET", url)
    except urllib_error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise

    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, list):
        raise RuntimeError(f"Unexpected response listing directory {path}")
    return payload


# Registration events, one JSON file per registration.

BEIJING_TZ = ZoneInfo("Asia/Shanghai")
TIMEZONE_LABEL = "CST"
_LOGS_DIR = "logs"


@dataclass(frozen=True)
class RegistrationEvent:
    """Data required to create a registration log entry."""

    timestamp: datetime
    rp_id: str
    aaguid: bytes | None
    device_name_mds: str | None
    attestation_object: bytes
    signature_valid: bool | None = None
    root_valid: bool | None = None
    rp_id_hash_valid: bool | None = None
    aaguid_match: bool | None = None


def to_b64url(data: bytes) -> str:
    """Encode *data* using base64url without padding."""

    if not data:
        return ""
    return encode_base64url(data)


def random_shortid(length: int = 8) -> str:
    """Return a cryptographically strong random identifier."""

    if length <= 0:
        raise ValueError("length must be positive")
    # token_hex returns two characters per byte; trim to the requested length.
    return secrets.token_hex((length + 1) // 2)[:length]


def uuid_bytes_to_str(value: bytes | None) -> str:
    """Convert binary UUID data to a canonical string representation."""

    if not value:
        return "unknown"
    try:
        if len(value) == 16:
            return str(uuid.UUID(bytes=value))
    except Exception:
        pass
    return to_b64url(value)


def safe_cbor_decode(data: bytes | str) -> Mapping[str, Any]:
    """Decode a CBOR payload into JSON-safe data.

    On failure a dictionary containing ``{"error": "decode_failed"}`` is returned.
    """

    payload: bytes | None
    if isinstance(data, (bytes, bytearray, memoryview)):
        payload = bytes(data)
    elif isinstance(data, str):
        payload = encoding.try_decode_base64url(data)
    else:
        payload = None

    if not payload:
        return {"error": "decode_failed"}

    try:
        decoded = cbor2.loads(payload)
    except Exception:
        return {"error": "decode_failed"}

    json_safe = make_json_safe(decoded, string_keys=True)
    if isinstance(json_safe, Mapping):
        return json_safe
    return {"value": json_safe}


def _log_path(aaguid: str, timestamp: datetime) -> str:
    folder_name = aaguid or "unknown"
    if "/" in folder_name or ".." in folder_name:
        folder_name = "unknown"
    timestamp_label = timestamp.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp_label}_{random_shortid(6)}.json"
    return f"{_LOGS_DIR}/{folder_name}/{filename}"


def _build_log_payload(event: RegistrationEvent) -> tuple[str, Mapping[str, Any], Mapping[str, str]]:
    timestamp_local = event.timestamp.astimezone(BEIJING_TZ).replace(microsecond=0)
    timestamp_iso = timestamp_local.isoformat()

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)

    attestation_bytes = bytes(event.attestation_object)
    attestation_raw = to_b64url(attestation_bytes)
    attestation_decoded = safe_cbor_decode(attestation_bytes)

    path = _log_path(aaguid_str, event.timestamp)

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "aaguid": aaguid_str,
        "device_name_mds": event.device_name_mds or "unknown",
        "raw_attestation_object": attestation_raw,
        "decoded_attestation_object": attestation_decoded,
        "signature_valid": event.signature_valid,
        "root_valid": event.root_valid,
        "rp_id_hash_valid": event.rp_id_hash_valid,
        "aaguid_match": event.aaguid_match,
    }

    summary: MutableMapping[str, str] = {
        "timestamp": timestamp_local.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "aaguid": aaguid_str,
        "device": event.device_name_mds or "unknown",
        "action": "create",
    }

    return path, payload, summary


def _upload_worker(
    path: str,
    payload: Mapping[str, Any],
    summary: Mapping[str, str],
) -> None:
    payload_dict: MutableMapping[str, Any] = dict(payload)
    summary_dict: MutableMapping[str, str] = dict(summary)

    try:
        github_upload_json(path, dict(payload_dict))
    except Exception as exc:
        logger.warning(
            "[%s %s] Failed to upload credential log %s: %s",
            TIMEZONE_LABEL,
            summary_dict.get("timestamp", ""),
            path,
            exc,
        )
        return

    logger.info(
        "[%s %s] Uploaded credential log AAGUID=%s device=%s action=%s",
        TIMEZONE_LABEL,
        summary_dict.get("timestamp", ""),
        summary_dict.get("aaguid"),
        summary_dict.get("device"),
        summary_dict.get("action"),
    )


def _should_upload_async() -> bool:
    """Return ``True`` when uploads should be handed off to a background thread."""

    explicit = parse_env_flag("GITHUB_LOG_ASYNC")
    if explicit is not None:
        return explicit

    # Cloud Run request-based services can throttle CPU after the HTTP response is
    # sent, so background uploads may never complete. Prefer inline delivery there.
    if os.environ.get("K_SERVICE"):
        return False

    return True


def record_registration_event(event: RegistrationEvent) -> None:
    """Serialize *event* and upload it to the credential log repository."""

    if not is_logging_enabled():
        logger.debug("GitHub credential logging disabled; skipping upload for rp_id=%s", event.rp_id)
        return

    path, payload, summary = _build_log_payload(event)
    if not _should_upload_async():
        _upload_worker(path, payload, summary)
        return

    thread = threading.Thread(
        target=_upload_worker,
        args=(path, payload, summary),
        daemon=True,
    )
    thread.start()


# Uploaded metadata, one copy per file.

_METADATA_REPO_FOLDER = "metadata"


def _safe_metadata_repo_filename(filename: str) -> str:
    candidate = os.path.basename(filename.strip()) if isinstance(filename, str) else ""
    if not candidate:
        return "metadata.json"
    return candidate


def maybe_store_uploaded_metadata_file(filename: str, content: bytes) -> bool:
    """Upload ``content`` to the credential log repository metadata folder."""

    if not content or not is_logging_enabled():
        return False

    safe_name = _safe_metadata_repo_filename(filename)

    try:
        existing_items = github_list_directory(_METADATA_REPO_FOLDER)
    except Exception as exc:  # pragma: no cover - best effort logging
        logger.warning("Unable to list metadata repository contents: %s", exc)
        return False

    blob_sha = git_blob_sha(content)
    existing_sha_for_name: str | None = None
    path_for_name: str | None = None

    for item in existing_items:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") != "file":
            continue

        item_sha = item.get("sha")
        if isinstance(item_sha, str) and item_sha == blob_sha:
            logger.info(
                "Skipping upload of metadata file %s; identical content already present as %s.",
                safe_name,
                item.get("name"),
            )
            return False

        if item.get("name") == safe_name and isinstance(item_sha, str):
            existing_sha_for_name = item_sha
            path_value = item.get("path")
            if isinstance(path_value, str):
                path_for_name = path_value

    remote_path = path_for_name or f"{_METADATA_REPO_FOLDER}/{safe_name}"
    action = "update" if existing_sha_for_name else "add"
    message = f"metadata: {action} {safe_name}"

    try:
        github_upload_file(remote_path, content, message, sha=existing_sha_for_name)
        return True
    except Exception as exc:  # pragma: no cover - best effort logging
        logger.warning("Failed to upload metadata file %s: %s", safe_name, exc)
        return False
