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


def _build_log_payload(event: RegistrationEvent) -> Tuple[str, MutableMapping[str, Any], Mapping[str, str]]:
    timestamp_utc = event.timestamp.astimezone(timezone.utc).replace(microsecond=0)
    timestamp_iso = timestamp_utc.isoformat().replace("+00:00", "Z")

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)
    digest = hashlib.sha256(bytes(event.attestation_object)).hexdigest()
    filename = f"{digest[:16]}_{aaguid_str}.json"
    path = f"{_LOGS_DIR}/{filename}"

    attestation_raw = to_b64url(bytes(event.attestation_object))
    attestation_decoded = safe_cbor_decode(event.attestation_object)

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "aaguid": aaguid_str,
        "device_name_mds": event.device_name_mds,
        "raw_attestation_object": attestation_raw,
        "decoded_attestation_object": attestation_decoded,
        "times_registered": 1,
    }

    timestamp_cst = timestamp_utc.astimezone(BEIJING_TZ)
    summary = {
        "timestamp": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_cst": timestamp_cst.replace(microsecond=0).isoformat(),
        "aaguid": aaguid_str,
        "device": event.device_name_mds or "unknown",
    }

    return path, payload, summary


def _upload_worker(path: str, payload: MutableMapping[str, Any], summary: Mapping[str, str]) -> None:
    existing_sha: Optional[str] = None
    updated = False
    try:
        existing = github_get_json(path)
    except Exception as exc:
        print(
            f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] "
            f"Failed to fetch existing credential log {path}: {exc}"
        )
        return

    if existing is not None:
        existing_payload, existing_sha = existing
        if existing_payload.get("raw_attestation_object") == payload.get("raw_attestation_object"):
            times_registered = existing_payload.get("times_registered")
            try:
                current_times = int(times_registered)
            except (TypeError, ValueError):
                current_times = 1
            payload["times_registered"] = current_times + 1
            updated = True
        else:
            existing_sha = None

    aaguid_display = payload.get("aaguid", "unknown") or "unknown"
    filename = path.split("/")[-1]
    action_word = "Updated" if updated else "Uploaded"
    message_action = "update" if updated else "add"

    try:
        github_upload_json(
            path,
            dict(payload),
            sha=existing_sha if updated else None,
            message=f"{message_action}: {filename} (AAGUID={aaguid_display})",
        )
    except Exception as exc:
        print(f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] Failed to upload credential log {path}: {exc}")
        return

    print(
        f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] "
        f"{action_word} credential log AAGUID={summary.get('aaguid')} "
        f"device={summary.get('device')} times={payload.get('times_registered')}"
    )


def record_registration_event(event: RegistrationEvent) -> None:
    """Serialize *event* and upload it to the credential log repository."""

    if not is_logging_enabled():
        _logger.debug("GitHub credential logging disabled; skipping upload for rp_id=%s", event.rp_id)
        return

    path, payload, summary = _build_log_payload(event)
    _schedule_cleanup_workflow_check()
    thread = threading.Thread(target=_upload_worker, args=(path, payload, summary), daemon=True)
    thread.start()
