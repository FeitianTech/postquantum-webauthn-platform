"""GitHub-based logging for WebAuthn device registrations."""
from __future__ import annotations

import logging
import os
import secrets
import threading
import uuid
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

import cbor2

from . import encoding
from .encoding import encode_base64url
from .env_flags import parse_env_flag
from .github_client import (
    github_upload_json,
    is_logging_enabled,
)
from .json_values import make_json_safe

__all__ = [
    "RegistrationEvent",
    "record_registration_event",
    "random_shortid",
    "safe_cbor_decode",
    "to_b64url",
    "uuid_bytes_to_str",
]


_logger = logging.getLogger(__name__)

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
        _logger.warning(
            "[%s %s] Failed to upload credential log %s: %s",
            TIMEZONE_LABEL,
            summary_dict.get("timestamp", ""),
            path,
            exc,
        )
        return

    _logger.info(
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
        _logger.debug("GitHub credential logging disabled; skipping upload for rp_id=%s", event.rp_id)
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
