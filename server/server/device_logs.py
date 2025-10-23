"""GitHub-based logging for WebAuthn device registrations."""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping, Optional, Sequence, Tuple

import cbor2

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for very old Python
    from backports.zoneinfo import ZoneInfo  # type: ignore

from .github_client import (
    ensure_cleanup_workflow,
    github_get_json,
    github_upload_json,
    is_logging_enabled,
)

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
    user_id: bytes
    user_name: str
    user_display_name: str
    credential_id: bytes
    public_key_cose: Mapping[Any, Any]
    sign_count: int
    transports: Optional[Sequence[str]]
    aaguid: Optional[bytes]
    device_name_mds: Optional[str]
    attestation_format: str
    attestation_object: bytes
    client_data_json: bytes


def to_b64url(data: bytes) -> str:
    """Encode *data* using base64url without padding."""

    if not data:
        return ""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def random_shortid(length: int = 8) -> str:
    """Return a cryptographically strong random identifier."""

    if length <= 0:
        raise ValueError("length must be positive")
    # token_hex returns two characters per byte; trim to the requested length.
    return secrets.token_hex((length + 1) // 2)[:length]


def uuid_bytes_to_str(value: Optional[bytes]) -> str:
    """Convert binary UUID data to a canonical string representation."""

    if not value:
        return "unknown"
    try:
        if len(value) == 16:
            return str(uuid.UUID(bytes=value))
    except Exception:
        pass
    return to_b64url(value)


def _json_safe(obj: Any) -> Any:
    """Recursively convert objects to JSON-safe representations."""

    if isinstance(obj, (bytes, bytearray, memoryview)):
        return to_b64url(bytes(obj))
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, Mapping):
        return {str(key): _json_safe(value) for key, value in obj.items()}
    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        return [_json_safe(item) for item in obj]
    return obj


def safe_cbor_decode(data: bytes | str) -> Mapping[str, Any]:
    """Decode a CBOR payload into JSON-safe data.

    On failure a dictionary containing ``{"error": "decode_failed"}`` is returned.
    """

    payload: Optional[bytes]
    if isinstance(data, (bytes, bytearray, memoryview)):
        payload = bytes(data)
    elif isinstance(data, str):
        candidate = data.strip()
        if not candidate:
            payload = None
        else:
            padding = "=" * (-len(candidate) % 4)
            try:
                payload = base64.urlsafe_b64decode(candidate + padding)
            except Exception:
                payload = None
    else:
        payload = None

    if not payload:
        return {"error": "decode_failed"}

    try:
        decoded = cbor2.loads(payload)
    except Exception:
        return {"error": "decode_failed"}

    json_safe = _json_safe(decoded)
    if isinstance(json_safe, Mapping):
        return json_safe
    return {"value": json_safe}


_cleanup_lock = threading.Lock()
_cleanup_scheduled = False


def _ensure_cleanup_workflow_async() -> None:
    try:
        ensure_cleanup_workflow()
    except Exception as exc:  # pragma: no cover - best-effort startup hook
        _logger.warning("Unable to ensure cleanup workflow: %s", exc)


def _schedule_cleanup_workflow_check() -> None:
    global _cleanup_scheduled
    with _cleanup_lock:
        if _cleanup_scheduled:
            return
        _cleanup_scheduled = True
    thread = threading.Thread(target=_ensure_cleanup_workflow_async, daemon=True)
    thread.start()


def _log_path(aaguid: str, attestation_object: bytes) -> str:
    digest = hashlib.sha256(attestation_object).hexdigest()
    safe_aaguid = aaguid or "unknown"
    filename = f"{safe_aaguid}_{digest}.json"
    return f"{_LOGS_DIR}/{filename}"


def _build_log_payload(event: RegistrationEvent) -> Tuple[str, Mapping[str, Any], Mapping[str, str], Optional[str]]:
    timestamp_utc = event.timestamp.astimezone(timezone.utc).replace(microsecond=0)
    timestamp_iso = timestamp_utc.isoformat().replace("+00:00", "Z")

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)

    attestation_bytes = bytes(event.attestation_object)
    attestation_raw = to_b64url(attestation_bytes)
    attestation_decoded = safe_cbor_decode(attestation_bytes)

    path = _log_path(aaguid_str, attestation_bytes)

    times_registered = 1
    sha: Optional[str] = None
    try:
        existing_payload, existing_sha = github_get_json(path)
    except FileNotFoundError:
        pass
    except Exception as exc:  # pragma: no cover - defensive logging
        _logger.warning("Unable to fetch existing credential log %s: %s", path, exc)
    else:
        existing_raw = existing_payload.get("raw_attestation_object")
        if isinstance(existing_raw, str) and existing_raw == attestation_raw:
            existing_times = existing_payload.get("times_registered", 1)
            try:
                times_registered = int(existing_times) + 1
            except Exception:
                times_registered = 2
            sha = existing_sha

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "aaguid": aaguid_str,
        "device_name_mds": event.device_name_mds or "unknown",
        "raw_attestation_object": attestation_raw,
        "decoded_attestation_object": attestation_decoded,
        "times_registered": times_registered,
    }

    timestamp_cst = timestamp_utc.astimezone(BEIJING_TZ)
    summary: MutableMapping[str, str] = {
        "timestamp": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_cst": timestamp_cst.replace(microsecond=0).isoformat(),
        "aaguid": aaguid_str,
        "device": event.device_name_mds or "unknown",
        "times_registered": str(times_registered),
        "action": "update" if sha else "create",
    }

    return path, payload, summary, sha


def _upload_worker(
    path: str,
    payload: Mapping[str, Any],
    summary: Mapping[str, str],
    sha: Optional[str],
) -> None:
    try:
        github_upload_json(path, dict(payload), sha=sha)
    except Exception as exc:
        print(f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] Failed to upload credential log {path}: {exc}")
        return

    verb = "Updated" if sha else "Uploaded"
    print(
        f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] "
        f"{verb} credential log AAGUID={summary.get('aaguid')} device={summary.get('device')} "
        f"times_registered={summary.get('times_registered')}"
    )


def record_registration_event(event: RegistrationEvent) -> None:
    """Serialize *event* and upload it to the credential log repository."""

    if not is_logging_enabled():
        _logger.debug("GitHub credential logging disabled; skipping upload for rp_id=%s", event.rp_id)
        return

    path, payload, summary, sha = _build_log_payload(event)
    _schedule_cleanup_workflow_check()
    thread = threading.Thread(
        target=_upload_worker,
        args=(path, payload, summary, sha),
        daemon=True,
    )
    thread.start()
