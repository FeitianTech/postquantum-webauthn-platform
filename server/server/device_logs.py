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
    github_delete,
    github_get_json,
    github_list_directory,
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
_ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"
_ZERO_AAGUID_FOLDER = f"{_LOGS_DIR}/zero-aaguid"


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


@dataclass(frozen=True)
class _LogUploadContext:
    payload: Mapping[str, Any]
    summary: Mapping[str, str]
    aaguid: str
    device_name: str
    sanitized_device_name: str
    attestation_format: str
    signature_algorithm: str
    attestation_bytes: bytes


def _sanitize_for_path_segment(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in {"-", " ", "."})
    cleaned = cleaned.replace("_", " ").strip()
    return " ".join(cleaned.split())


def _sanitize_device_name(device_name: str) -> str:
    if device_name.lower() == "unknown":
        return ""
    sanitized = _sanitize_for_path_segment(device_name)
    return sanitized


def _sanitize_filename_component(value: str) -> str:
    sanitized = value.replace(" ", "-").replace("/", "-").replace("_", "-")
    sanitized = "".join(ch for ch in sanitized if ch.isalnum() or ch in {"-", "."})
    return sanitized or "unknown"


def _signature_algorithm_from_cose(public_key_cose: Mapping[Any, Any]) -> str:
    alg: Any
    try:
        alg = public_key_cose.get(3, "unknown")
    except Exception:
        alg = "unknown"
    if isinstance(alg, int):
        return str(alg)
    if isinstance(alg, str):
        return alg
    return "unknown"


def _is_zero_aaguid(aaguid: str) -> bool:
    if not aaguid:
        return False
    return aaguid.replace("-", "").lower() == "0" * 32


def _create_zero_aaguid_filename(attestation_bytes: bytes) -> str:
    digest = hashlib.sha256(attestation_bytes).hexdigest()[:10]
    return f"{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}-{random_shortid(6)}-{digest}.json"


def _create_default_filename(attestation_format: str, signature_algorithm: str, attestation_bytes: bytes) -> str:
    digest = hashlib.sha256(attestation_bytes).hexdigest()[:16]
    format_component = _sanitize_filename_component(attestation_format)
    alg_component = _sanitize_filename_component(signature_algorithm or "unknown")
    return f"{format_component}-{alg_component}-{digest}.json"


def _list_directory(path: str) -> Sequence[Mapping[str, Any]]:
    try:
        return github_list_directory(path)
    except Exception as exc:  # pragma: no cover - best-effort directory listing
        _logger.warning("Unable to list directory %s: %s", path, exc)
        return []


def _locate_aaguid_folder(aaguid: str, sanitized_device_name: str) -> Tuple[str, bool, Optional[str]]:
    base_name = aaguid or "unknown"
    target_name = base_name
    if sanitized_device_name:
        target_name = f"{base_name} {sanitized_device_name}"

    entries = _list_directory(_LOGS_DIR)
    fallback_plain: Optional[str] = None
    fallback_with_device: Optional[str] = None
    for entry in entries:
        if entry.get("type") != "dir":
            continue
        name = entry.get("name", "")
        if name == target_name:
            return name, False, None
        if name == base_name:
            fallback_plain = name
        elif name.startswith(f"{base_name} "):
            fallback_with_device = name

    if sanitized_device_name:
        if fallback_plain:
            return fallback_plain, True, target_name
        if fallback_with_device:
            return fallback_with_device, False, None
        return target_name, False, None

    if fallback_with_device:
        return fallback_with_device, False, None
    if fallback_plain:
        return fallback_plain, False, None
    return target_name, False, None


def _move_aaguid_folder(old_name: str, new_name: str) -> None:
    source_path = f"{_LOGS_DIR}/{old_name}"
    target_path = f"{_LOGS_DIR}/{new_name}"
    entries = _list_directory(source_path)
    for entry in entries:
        if entry.get("type") != "file":
            continue
        filename = entry.get("name")
        if not filename:
            continue
        old_file_path = f"{source_path}/{filename}"
        new_file_path = f"{target_path}/{filename}"
        try:
            existing_payload, existing_sha = github_get_json(old_file_path)
        except FileNotFoundError:
            continue
        except Exception as exc:  # pragma: no cover - best-effort migration
            _logger.warning("Unable to read %s during folder move: %s", old_file_path, exc)
            continue
        try:
            github_upload_json(new_file_path, dict(existing_payload))
        except Exception as exc:  # pragma: no cover - best-effort migration
            _logger.warning("Unable to write %s during folder move: %s", new_file_path, exc)
            continue
        try:
            github_delete(
                old_file_path,
                existing_sha,
                message=f"remove: {old_file_path}",
            )
        except Exception as exc:  # pragma: no cover - best-effort migration
            _logger.warning("Unable to delete %s during folder move: %s", old_file_path, exc)


def _find_existing_log(
    folder_path: str,
    attestation_format: str,
    signature_algorithm: str,
    device_name: str,
) -> Optional[Tuple[str, Mapping[str, Any], str]]:
    entries = _list_directory(folder_path)
    for entry in entries:
        if entry.get("type") != "file":
            continue
        filename = entry.get("name")
        if not filename or not filename.endswith(".json"):
            continue
        file_path = f"{folder_path}/{filename}"
        try:
            existing_payload, existing_sha = github_get_json(file_path)
        except FileNotFoundError:
            continue
        except Exception as exc:  # pragma: no cover - best-effort fetch
            _logger.warning("Unable to fetch existing credential log %s: %s", file_path, exc)
            continue
        existing_format = existing_payload.get("attestation_format", "")
        existing_alg = str(existing_payload.get("signature_algorithm", "unknown"))
        existing_device = existing_payload.get("device_name_mds", "unknown")
        if (
            existing_format == attestation_format
            and str(existing_alg) == str(signature_algorithm)
            and (existing_device or "unknown") == (device_name or "unknown")
        ):
            return file_path, existing_payload, existing_sha
    return None


def _build_log_payload(event: RegistrationEvent) -> _LogUploadContext:
    timestamp_local = event.timestamp.astimezone(BEIJING_TZ).replace(microsecond=0)
    timestamp_iso = timestamp_local.isoformat()

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)

    attestation_bytes = bytes(event.attestation_object)
    attestation_raw = to_b64url(attestation_bytes)
    attestation_decoded = safe_cbor_decode(attestation_bytes)

    device_name = event.device_name_mds or "unknown"
    signature_algorithm = _signature_algorithm_from_cose(event.public_key_cose)
    sanitized_device_name = _sanitize_device_name(device_name)

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "aaguid": aaguid_str,
        "device_name_mds": device_name,
        "attestation_format": event.attestation_format,
        "signature_algorithm": signature_algorithm,
        "raw_attestation_object": attestation_raw,
        "decoded_attestation_object": attestation_decoded,
        "times_registered": 1,
    }

    summary: MutableMapping[str, str] = {
        "timestamp": timestamp_local.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "aaguid": aaguid_str,
        "device": device_name,
        "times_registered": "1",
        "action": "create",
    }

    return _LogUploadContext(
        payload=dict(payload),
        summary=dict(summary),
        aaguid=aaguid_str,
        device_name=device_name,
        sanitized_device_name=sanitized_device_name,
        attestation_format=event.attestation_format,
        signature_algorithm=signature_algorithm,
        attestation_bytes=attestation_bytes,
    )


def _upload_worker(
    context: _LogUploadContext,
) -> None:
    payload_dict: MutableMapping[str, Any] = dict(context.payload)
    summary_dict: MutableMapping[str, str] = dict(context.summary)

    sha: Optional[str] = None
    path: Optional[str] = None
    folder_path: str

    if _is_zero_aaguid(context.aaguid):
        folder_path = _ZERO_AAGUID_FOLDER
        filename = _create_zero_aaguid_filename(context.attestation_bytes)
        path = f"{folder_path}/{filename}"
        times_registered = 1
    else:
        folder_name, needs_rename, desired_name = _locate_aaguid_folder(
            context.aaguid or "unknown", context.sanitized_device_name
        )
        if needs_rename and desired_name:
            try:
                _move_aaguid_folder(folder_name, desired_name)
                folder_name = desired_name
            except Exception as exc:  # pragma: no cover - best-effort rename
                _logger.warning(
                    "Unable to rename folder %s to %s: %s", folder_name, desired_name, exc
                )
        folder_path = f"{_LOGS_DIR}/{folder_name}"
        match = _find_existing_log(
            folder_path,
            context.attestation_format,
            context.signature_algorithm,
            context.device_name,
        )
        if match is not None:
            path, existing_payload, sha = match
            existing_times = existing_payload.get("times_registered", 1)
            try:
                times_registered = int(existing_times) + 1
            except Exception:
                times_registered = 2
            summary_dict["action"] = "update"
        else:
            filename = _create_default_filename(
                context.attestation_format,
                context.signature_algorithm,
                context.attestation_bytes,
            )
            path = f"{folder_path}/{filename}"
            times_registered = 1

    payload_dict["times_registered"] = times_registered
    summary_dict["times_registered"] = str(times_registered)

    try:
        if sha is None:
            github_upload_json(path, dict(payload_dict))
        else:
            github_upload_json(path, dict(payload_dict), sha=sha)
    except Exception as exc:
        print(
            f"[{TIMEZONE_LABEL} {summary_dict.get('timestamp', '')}] "
            f"Failed to upload credential log {path}: {exc}"
        )
        return

    verb = "Updated" if sha else "Uploaded"
    print(
        f"[{TIMEZONE_LABEL} {summary_dict.get('timestamp', '')}] "
        f"{verb} credential log AAGUID={summary_dict.get('aaguid')} device={summary_dict.get('device')} "
        f"times_registered={summary_dict.get('times_registered')}"
    )


def record_registration_event(event: RegistrationEvent) -> None:
    """Serialize *event* and upload it to the credential log repository."""

    if not is_logging_enabled():
        _logger.debug("GitHub credential logging disabled; skipping upload for rp_id=%s", event.rp_id)
        return

    context = _build_log_payload(event)
    _schedule_cleanup_workflow_check()
    thread = threading.Thread(
        target=_upload_worker,
        args=(context,),
        daemon=True,
    )
    thread.start()
