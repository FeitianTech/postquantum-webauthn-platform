"""GitHub-based logging for WebAuthn device registrations."""
from __future__ import annotations

import base64
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

from .github_client import ensure_cleanup_workflow, github_upload_json

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


def _ensure_cleanup_workflow_async() -> None:
    try:
        ensure_cleanup_workflow()
    except Exception as exc:  # pragma: no cover - best-effort startup hook
        _logger.warning("Unable to ensure cleanup workflow: %s", exc)


threading.Thread(target=_ensure_cleanup_workflow_async, daemon=True).start()


def _normalise_transports(transports: Optional[Sequence[str]]) -> Sequence[str]:
    if not transports:
        return ()
    normalised = []
    for item in transports:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                normalised.append(stripped)
    return tuple(normalised)


def _build_log_payload(event: RegistrationEvent) -> Tuple[str, Mapping[str, Any], Mapping[str, str]]:
    timestamp_utc = event.timestamp.astimezone(timezone.utc).replace(microsecond=0)
    timestamp_iso = timestamp_utc.isoformat().replace("+00:00", "Z")
    timestamp_filename = timestamp_utc.strftime("%Y-%m-%dT%H-%M-%SZ")

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)
    random_suffix = random_shortid(8)
    filename = f"{timestamp_filename}_{aaguid_str}_{random_suffix}.json"
    path = f"{_LOGS_DIR}/{filename}"

    attestation_raw = to_b64url(bytes(event.attestation_object))
    attestation_decoded = safe_cbor_decode(event.attestation_object)

    transports = list(_normalise_transports(event.transports))

    credential_payload: MutableMapping[str, Any] = {
        "credential_id": to_b64url(bytes(event.credential_id)),
        "public_key_cose": _json_safe(dict(event.public_key_cose)),
        "sign_count": int(event.sign_count),
        "transports": transports,
    }

    if aaguid_str != "unknown":
        credential_payload["aaguid"] = aaguid_str
    if event.device_name_mds:
        credential_payload["device_name_mds"] = event.device_name_mds

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "user": {
            "id": to_b64url(bytes(event.user_id)),
            "name": event.user_name,
            "display_name": event.user_display_name,
        },
        "credential": credential_payload,
        "attestation": {
            "format": event.attestation_format,
            "raw_attestation_object": attestation_raw,
            "decoded": attestation_decoded,
        },
        "client_data_json": to_b64url(bytes(event.client_data_json)),
    }

    timestamp_cst = timestamp_utc.astimezone(BEIJING_TZ)
    summary = {
        "timestamp": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_cst": timestamp_cst.replace(microsecond=0).isoformat(),
        "aaguid": aaguid_str,
        "device": event.device_name_mds or "unknown",
    }

    return path, payload, summary


def _upload_worker(path: str, payload: Mapping[str, Any], summary: Mapping[str, str]) -> None:
    try:
        github_upload_json(path, dict(payload))
    except Exception as exc:
        print(f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] Failed to upload credential log {path}: {exc}")
        return

    print(
        f"[{TIMEZONE_LABEL} {summary.get('timestamp', '')}] "
        f"Uploaded credential log AAGUID={summary.get('aaguid')} device={summary.get('device')}"
    )


def record_registration_event(event: RegistrationEvent) -> None:
    """Serialize *event* and upload it to the credential log repository."""

    path, payload, summary = _build_log_payload(event)
    thread = threading.Thread(target=_upload_worker, args=(path, payload, summary), daemon=True)
    thread.start()
