"""Metadata handling utilities for the WebAuthn demo server."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from flask import after_this_request, g, has_request_context, request, session

from fido2.mds3 import (
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
    MdsAttestationVerifier,
)

from . import session_metadata_store
from .config import (
    MDS_EXPLORER_PATH,
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_PATH,
    MDS_METADATA_VERIFIED_PATH,
    MDS_METADATA_URL,
    app,
)
from .github_client import (
    git_blob_sha,
    github_list_directory,
    github_upload_file,
    is_logging_enabled,
)
from .mds_snapshot import (
    build_entry_id,
    build_bootstrap_snapshot,
    build_explorer_entry,
    build_explorer_snapshot,
    normalise_aaguid_key,
)

__all__ = [
    "MetadataDownloadError",
    "download_metadata_blob",
    "get_mds_verifier",
    "load_metadata_cache_entry",
    "format_last_modified_header",
    "store_metadata_cache_entry",
    "load_cached_metadata_snapshot",
    "load_packaged_explorer_summary",
    "load_effective_explorer_snapshot",
    "load_effective_full_snapshot",
    "resolve_effective_metadata_entry",
    "ensure_metadata_session_id",
    "list_session_metadata_items",
    "save_session_metadata_item",
    "serialize_session_metadata_item",
    "delete_session_metadata_item",
    "expand_metadata_entry_payloads",
    "metadata_entry_trust_anchor_status",
    "maybe_store_uploaded_metadata_file",
]


_base_metadata_cache: Optional[MetadataBlobPayload] = None
_base_metadata_mtime: Optional[float] = None
_base_metadata_source: Optional[str] = None
_base_verifier_cache: Optional[MdsAttestationVerifier] = None
_base_verifier_mtime: Optional[float] = None
_base_metadata_trust_verified: Optional[bool] = None
_base_metadata_entry_ids: Set[int] = set()
_base_explorer_snapshot_cache: Optional[Dict[str, Any]] = None
_base_explorer_snapshot_mtime: Optional[Tuple[Optional[float], Optional[float]]] = None
_base_full_snapshot_cache: Optional[Dict[str, Any]] = None
_base_full_snapshot_mtime: Optional[float] = None
_session_metadata_entry_ids: Set[int] = set()

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"

_SESSION_METADATA_COOKIE_NAME = "fido.mds.session"
_SESSION_METADATA_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
_SESSION_METADATA_INACTIVE_AGE = timedelta(days=14)

_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV = (
    "FIDO_SERVER_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS"
)
_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_HOURS"
_SESSION_METADATA_CLEANUP_ASYNC_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_ASYNC"

_session_metadata_last_cleanup: float = 0.0
_session_cleanup_worker: Optional[threading.Thread] = None
_session_cleanup_pending: bool = False
_session_cleanup_lock = threading.Lock()

_METADATA_REPO_FOLDER = "metadata"

_METADATA_STATEMENT_REQUIRED_DEFAULTS: Mapping[str, Any] = {
    "description": "",
    "authenticatorVersion": 0,
    "schema": 3,
    "upv": [],
    "attestationTypes": [],
    "userVerificationDetails": [],
    "keyProtection": [],
    "matcherProtection": [],
    "attachmentHint": [],
    "tcDisplay": [],
    "attestationRootCertificates": [],
}


def _env_flag(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None

    normalised = raw.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True


def _resolve_cleanup_interval() -> timedelta:
    raw_seconds = os.environ.get(_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV)
    if raw_seconds is not None:
        try:
            seconds = float(raw_seconds)
            if seconds >= 0:
                return timedelta(seconds=seconds)
        except ValueError:
            app.logger.warning(
                "Invalid value for %s: %r",
                _SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV,
                raw_seconds,
            )

    raw_hours = os.environ.get(_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV)
    if raw_hours is not None:
        try:
            hours = float(raw_hours)
            if hours >= 0:
                return timedelta(hours=hours)
        except ValueError:
            app.logger.warning(
                "Invalid value for %s: %r",
                _SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV,
                raw_hours,
            )

    return timedelta(hours=6)


_SESSION_METADATA_CLEANUP_INTERVAL = _resolve_cleanup_interval()


def _cleanup_async_enabled() -> bool:
    explicit = _env_flag(_SESSION_METADATA_CLEANUP_ASYNC_ENV)
    if explicit is None:
        return True
    return explicit


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
        app.logger.warning("Unable to list metadata repository contents: %s", exc)
        return False

    blob_sha = git_blob_sha(content)
    existing_sha_for_name: Optional[str] = None
    path_for_name: Optional[str] = None

    for item in existing_items:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") != "file":
            continue

        item_sha = item.get("sha")
        if isinstance(item_sha, str) and item_sha == blob_sha:
            app.logger.info(
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
        app.logger.warning("Failed to upload metadata file %s: %s", safe_name, exc)
        return False


@dataclass(frozen=True)
class SessionMetadataItem:
    filename: str
    payload: Dict[str, Any]
    legal_header: Optional[str]
    entry: MetadataBlobPayloadEntry
    uploaded_at: Optional[str]
    original_filename: Optional[str]
    mtime: Optional[float]


def _normalise_session_identifier(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


def _schedule_session_cookie(identifier: str) -> None:
    if not has_request_context():
        return

    normalised = _normalise_session_identifier(identifier)
    if not normalised:
        return

    _note_session_activity(normalised)

    secure = bool(request.is_secure)
    cookie_path = "/"
    samesite = "None" if secure else "Lax"

    if getattr(g, "_session_metadata_cookie", None) == normalised:
        return

    g._session_metadata_cookie = normalised

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            _SESSION_METADATA_COOKIE_NAME,
            normalised,
            max_age=_SESSION_METADATA_COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path=cookie_path,
        )
        return response


def _get_metadata_session_id(*, create: bool = False) -> Optional[str]:
    if not has_request_context():
        return None

    cookie_identifier = _normalise_session_identifier(
        request.cookies.get(_SESSION_METADATA_COOKIE_NAME)
    )
    if cookie_identifier:
        session[_SESSION_METADATA_SESSION_KEY] = cookie_identifier
        _schedule_session_cookie(cookie_identifier)
        return cookie_identifier

    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str):
        identifier = _normalise_session_identifier(existing)
        if identifier:
            session[_SESSION_METADATA_SESSION_KEY] = identifier
            _schedule_session_cookie(identifier)
            return identifier

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
    _schedule_session_cookie(identifier)
    return identifier


def ensure_metadata_session_id() -> str:
    identifier = _get_metadata_session_id(create=True)
    if not identifier:
        raise RuntimeError("Unable to establish metadata session identifier.")
    if has_request_context():
        session.permanent = True
    return identifier


def _session_metadata_directory(
    session_id: str, *, create: bool = False, cleanup: bool = True
) -> Optional[str]:
    if not session_id:
        return None

    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return None

    if create:
        try:
            session_metadata_store.ensure_session(normalised)
        except Exception as exc:
            app.logger.error(
                "Failed to prepare session metadata storage for %s: %s", normalised, exc
            )
            raise
    if cleanup:
        _schedule_inactive_session_cleanup()
    return normalised


def _touch_session_last_access(session_id: str) -> None:
    try:
        session_metadata_store.touch_last_access(session_id)
    except Exception:
        pass


def _resolve_session_last_access(session_id: str) -> Optional[float]:
    try:
        return session_metadata_store.resolve_last_access(session_id)
    except Exception:
        return None


def _maybe_cleanup_inactive_sessions(now: Optional[float] = None) -> None:
    global _session_metadata_last_cleanup

    current_time = now or time.time()
    if current_time - _session_metadata_last_cleanup < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds():
        return

    _session_metadata_last_cleanup = current_time
    cutoff = current_time - _SESSION_METADATA_INACTIVE_AGE.total_seconds()

    try:
        sessions = session_metadata_store.list_sessions()
    except Exception:
        return

    for session_id in sessions:
        last_access = _resolve_session_last_access(session_id)
        if last_access is None or last_access >= cutoff:
            continue

        try:
            session_metadata_store.delete_session(session_id)
        except Exception as exc:
            app.logger.warning(
                "Failed to remove inactive metadata session %s: %s", session_id, exc
            )


def _run_inactive_session_cleanup_worker() -> None:
    global _session_cleanup_worker, _session_cleanup_pending

    while True:
        try:
            _maybe_cleanup_inactive_sessions()
        except Exception as exc:  # pragma: no cover - defensive logging
            app.logger.warning(
                "Unexpected failure while cleaning inactive metadata sessions: %s",
                exc,
                exc_info=True,
            )

        with _session_cleanup_lock:
            if _session_cleanup_pending:
                _session_cleanup_pending = False
                continue

            _session_cleanup_worker = None
            return


def _schedule_inactive_session_cleanup() -> None:
    global _session_cleanup_worker, _session_cleanup_pending

    current_time = time.time()
    if (
        current_time - _session_metadata_last_cleanup
        < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds()
    ):
        return

    if not _cleanup_async_enabled():
        _maybe_cleanup_inactive_sessions(now=current_time)
        return

    worker: Optional[threading.Thread] = None

    with _session_cleanup_lock:
        if _session_cleanup_worker is not None and _session_cleanup_worker.is_alive():
            _session_cleanup_pending = True
            return

        worker = threading.Thread(
            target=_run_inactive_session_cleanup_worker,
            name="session-metadata-cleanup",
            daemon=True,
        )
        _session_cleanup_worker = worker

    try:
        worker.start()
    except RuntimeError:  # pragma: no cover - defensive fallback
        with _session_cleanup_lock:
            if _session_cleanup_worker is worker:
                _session_cleanup_worker = None
                _session_cleanup_pending = False
        _maybe_cleanup_inactive_sessions(now=current_time)


def _note_session_activity(session_id: str, *, directory: Optional[str] = None) -> None:
    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return

    _touch_session_last_access(normalised)
    _schedule_inactive_session_cleanup()


def _validate_session_metadata_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise ValueError("Invalid metadata filename.")

    trimmed = filename.strip()
    if not trimmed:
        raise ValueError("Invalid metadata filename.")

    if trimmed.startswith("."):
        raise ValueError("Invalid metadata filename.")

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            raise ValueError("Invalid metadata filename.")

    if os.path.basename(trimmed) != trimmed:
        raise ValueError("Invalid metadata filename.")

    if not trimmed.endswith(_SESSION_METADATA_SUFFIX):
        raise ValueError("Invalid metadata filename.")

    return trimmed


def _prune_session_metadata_directory(session_id: str) -> None:
    try:
        session_metadata_store.prune_session(session_id)
    except Exception:
        pass


def _load_session_metadata_info(session_id: str, filename: str) -> Dict[str, Any]:
    try:
        payload_bytes = session_metadata_store.read_file(session_id, filename)
    except Exception:
        return {}

    if not payload_bytes:
        return {}

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    return payload


def _clone_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return None


def _normalise_status_reports(raw: Mapping[str, Any]) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    value = raw.get("statusReports")
    if not isinstance(value, list):
        return reports

    for entry in value:
        cloned = _clone_json_value(entry)
        if isinstance(cloned, dict):
            reports.append(cloned)
    return reports


def _normalise_attestation_identifiers(raw: Mapping[str, Any]) -> Optional[List[str]]:
    identifiers = raw.get("attestationCertificateKeyIdentifiers")
    if not isinstance(identifiers, list):
        return None

    filtered: List[str] = []
    for identifier in identifiers:
        if isinstance(identifier, str):
            trimmed = identifier.strip()
            if trimmed:
                filtered.append(trimmed)
    return filtered or None


def _normalise_metadata_statement(raw: Mapping[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    legal_header: Optional[str] = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str):
        legal_header = raw_legal_header.strip() or None

    metadata_source: Mapping[str, Any] = raw
    nested_statement = raw.get("metadataStatement")
    if isinstance(nested_statement, Mapping):
        metadata_source = nested_statement

    excluded_keys = {
        "statusReports",
        "timeOfLastStatusChange",
        "attestationCertificateKeyIdentifiers",
        "aaid",
        "aaguid",
    }

    metadata_statement: Dict[str, Any] = {}
    for key, value in metadata_source.items():
        if metadata_source is raw and key in excluded_keys:
            continue

        cloned = _clone_json_value(value)
        if cloned is not None:
            metadata_statement[key] = cloned

    if legal_header and "legalHeader" not in metadata_statement:
        metadata_statement["legalHeader"] = legal_header

    description = metadata_statement.get("description")
    if not isinstance(description, str):
        metadata_statement["description"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["description"]

    authenticator_version = metadata_statement.get("authenticatorVersion")
    if not isinstance(authenticator_version, int):
        metadata_statement["authenticatorVersion"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["authenticatorVersion"]

    schema = metadata_statement.get("schema")
    if not isinstance(schema, int):
        metadata_statement["schema"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["schema"]

    for key in (
        "upv",
        "attestationTypes",
        "userVerificationDetails",
        "keyProtection",
        "matcherProtection",
        "attachmentHint",
        "tcDisplay",
        "attestationRootCertificates",
    ):
        value = metadata_statement.get(key)
        if not isinstance(value, list):
            default_value = _METADATA_STATEMENT_REQUIRED_DEFAULTS[key]
            metadata_statement[key] = list(default_value) if isinstance(default_value, list) else default_value

    return metadata_statement, legal_header


def build_metadata_entry_components(raw: Mapping[str, Any]) -> Tuple[
    MetadataBlobPayloadEntry,
    Optional[str],
    Dict[str, Any],
]:
    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    payload: Dict[str, Any] = {}
    payload["statusReports"] = _normalise_status_reports(raw)

    time_of_last_status_change = raw.get("timeOfLastStatusChange")
    if isinstance(time_of_last_status_change, str) and time_of_last_status_change.strip():
        payload["timeOfLastStatusChange"] = time_of_last_status_change.strip()
    else:
        payload["timeOfLastStatusChange"] = datetime.now(timezone.utc).date().isoformat()

    identifiers = _normalise_attestation_identifiers(raw)
    if identifiers:
        payload["attestationCertificateKeyIdentifiers"] = identifiers

    if isinstance(raw.get("aaid"), str) and raw["aaid"].strip():
        payload["aaid"] = raw["aaid"].strip()

    if isinstance(raw.get("aaguid"), str) and raw["aaguid"].strip():
        payload["aaguid"] = raw["aaguid"].strip()

    metadata_statement, legal_header = _normalise_metadata_statement(raw)
    payload["metadataStatement"] = metadata_statement

    entry = MetadataBlobPayloadEntry.from_dict(payload)
    payload_clone = json.loads(json.dumps(payload))
    return entry, legal_header, payload_clone


def expand_metadata_entry_payloads(raw: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """Expand a JSON payload into individual metadata entries.

    The FIDO Metadata BLOB contains an ``entries`` list with metadata
    statements. Uploaded JSON snippets may either provide a single metadata
    entry object or a structure mirroring the BLOB shape. This helper
    normalises both cases into a list of per-entry payload mappings that can be
    handed to :func:`build_metadata_entry_components`.
    """

    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    entries_value = raw.get("entries")
    if not isinstance(entries_value, list):
        return [raw]

    if not entries_value:
        raise ValueError("Metadata JSON does not contain any entries.")

    legal_header: Optional[str] = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str) and raw_legal_header.strip():
        legal_header = raw_legal_header.strip()

    expanded: List[Mapping[str, Any]] = []
    for index, entry in enumerate(entries_value):
        if not isinstance(entry, Mapping):
            raise ValueError(f"Entry {index + 1} is not a JSON object.")

        cloned = _clone_json_value(entry)
        if not isinstance(cloned, dict):
            raise ValueError(f"Entry {index + 1} could not be cloned into a JSON object.")

        if legal_header and "legalHeader" not in cloned:
            cloned["legalHeader"] = legal_header

        expanded.append(cloned)

    return expanded


def _normalise_aaguid(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("-", "").lower()
    return cleaned or None


def _extract_entry_aaguid(entry: MetadataBlobPayloadEntry) -> Optional[str]:
    direct = _normalise_aaguid(getattr(entry, "aaguid", None))
    if direct:
        return direct

    statement = getattr(entry, "metadata_statement", None)
    if statement is None:
        statement = getattr(entry, "metadataStatement", None)
    if isinstance(statement, Mapping):
        return _normalise_aaguid(statement.get("aaguid"))
    return None


def _merge_metadata(
    base_metadata: Optional[MetadataBlobPayload],
    session_items: List[SessionMetadataItem],
) -> MetadataBlobPayload:
    custom_entries: List[MetadataBlobPayloadEntry] = []
    seen_aaguids: Set[str] = set()

    for item in session_items:
        entry = item.entry
        aaguid = _extract_entry_aaguid(entry)
        if aaguid and aaguid in seen_aaguids:
            continue
        if aaguid:
            seen_aaguids.add(aaguid)
        custom_entries.append(entry)

    base_entries: List[MetadataBlobPayloadEntry] = []
    if base_metadata is not None:
        for entry in base_metadata.entries:
            aaguid = _extract_entry_aaguid(entry)
            if aaguid and aaguid in seen_aaguids:
                continue
            base_entries.append(entry)

    combined_entries = tuple(custom_entries + base_entries)
    if base_metadata is not None:
        metadata = replace(base_metadata, entries=combined_entries)
        if not getattr(metadata, "legal_header", None):
            for item in session_items:
                if item.legal_header:
                    metadata = replace(metadata, legal_header=item.legal_header)
                    break
        return metadata

    legal_header = ""
    for item in session_items:
        if item.legal_header:
            legal_header = item.legal_header
            break

    next_update = datetime.now(timezone.utc).date()
    return MetadataBlobPayload(
        legal_header=legal_header,
        no=0,
        next_update=next_update,
        entries=combined_entries,
    )


def save_session_metadata_item(
    raw_payload: Mapping[str, Any],
    *,
    original_filename: Optional[str] = None,
) -> SessionMetadataItem:
    session_id = ensure_metadata_session_id()
    directory = _session_metadata_directory(session_id, create=True)
    if not directory:
        raise RuntimeError("Unable to resolve session metadata storage path.")

    entry, legal_header, payload = build_metadata_entry_components(raw_payload)

    try:
        serialisable_payload = json.loads(json.dumps(raw_payload))
    except (TypeError, ValueError) as exc:
        raise ValueError("Metadata JSON contains unsupported types.") from exc

    stored_filename = f"{uuid.uuid4().hex}{_SESSION_METADATA_SUFFIX}"
    json_payload = json.dumps(serialisable_payload, indent=2, sort_keys=True) + "\n"

    try:
        session_metadata_store.write_file(
            directory,
            stored_filename,
            json_payload.encode("utf-8"),
            content_type="application/json",
        )
    except Exception as exc:
        app.logger.error(
            "Failed to store session metadata %s: %s", stored_filename, exc
        )
        raise RuntimeError("Failed to store uploaded metadata on the server.") from exc

    uploaded_at = datetime.now(timezone.utc).isoformat()
    info_payload = {
        "original_filename": original_filename or None,
        "uploaded_at": uploaded_at,
        "stored_filename": stored_filename,
    }

    info_json = json.dumps(info_payload, indent=2, sort_keys=True) + "\n"
    info_filename = f"{stored_filename}{_SESSION_METADATA_INFO_SUFFIX}"
    try:
        session_metadata_store.write_file(
            directory,
            info_filename,
            info_json.encode("utf-8"),
            content_type="application/json",
        )
    except Exception as exc:
        app.logger.warning(
            "Failed to store session metadata info for %s: %s", stored_filename, exc
        )

    try:
        mtime = session_metadata_store.file_mtime(directory, stored_filename)
    except Exception:
        mtime = None

    return SessionMetadataItem(
        filename=stored_filename,
        payload=payload,
        legal_header=legal_header,
        entry=entry,
        uploaded_at=uploaded_at,
        original_filename=original_filename or None,
        mtime=mtime,
    )


def list_session_metadata_items(session_id: Optional[str] = None) -> List[SessionMetadataItem]:
    global _session_metadata_entry_ids
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        _session_metadata_entry_ids = set()
        return []

    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        _session_metadata_entry_ids = set()
        return []

    _note_session_activity(active_session, directory=directory)

    try:
        filenames = [
            name
            for name in session_metadata_store.list_files(directory)
            if name.endswith(_SESSION_METADATA_SUFFIX)
            and not name.endswith(_SESSION_METADATA_INFO_SUFFIX)
        ]
    except Exception:
        return []

    items: List[SessionMetadataItem] = []
    for filename in sorted(filenames):
        try:
            payload_bytes = session_metadata_store.read_file(directory, filename)
            raw = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else None
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            app.logger.warning(
                "Failed to load session metadata from %s/%s: %s", directory, filename, exc
            )
            continue

        try:
            entry, legal_header, payload = build_metadata_entry_components(raw)
        except Exception as exc:  # pylint: disable=broad-except
            app.logger.warning(
                "Failed to parse session metadata entry from %s/%s: %s",
                directory,
                filename,
                exc,
            )
            continue

        info_filename = f"{filename}{_SESSION_METADATA_INFO_SUFFIX}"
        info = _load_session_metadata_info(directory, info_filename)

        raw_uploaded_at = info.get("uploaded_at")
        uploaded_at = raw_uploaded_at.strip() if isinstance(raw_uploaded_at, str) else None
        raw_original_name = info.get("original_filename")
        original_filename = (
            raw_original_name.strip() if isinstance(raw_original_name, str) and raw_original_name.strip() else None
        )

        try:
            mtime = session_metadata_store.file_mtime(directory, filename)
        except Exception:
            mtime = None

        items.append(
            SessionMetadataItem(
                filename=filename,
                payload=payload,
                legal_header=legal_header,
                entry=entry,
                uploaded_at=uploaded_at,
                original_filename=original_filename,
                mtime=mtime,
            )
        )

    items.sort(key=lambda item: item.mtime or 0, reverse=True)
    _session_metadata_entry_ids = {id(item.entry) for item in items}
    return items


def delete_session_metadata_item(
    stored_filename: str, session_id: Optional[str] = None
) -> bool:
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        raise ValueError("No active metadata session.")

    safe_name = _validate_session_metadata_filename(stored_filename)
    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        return False

    _note_session_activity(active_session, directory=directory)

    try:
        exists = session_metadata_store.file_exists(directory, safe_name)
    except Exception:
        exists = False

    if not exists:
        return False

    try:
        session_metadata_store.delete_file(directory, safe_name, missing_ok=False)
    except Exception as exc:
        app.logger.error(
            "Failed to delete session metadata %s/%s: %s", directory, safe_name, exc
        )
        raise RuntimeError("Failed to delete the uploaded metadata file.") from exc

    try:
        session_metadata_store.delete_file(
            directory, f"{safe_name}{_SESSION_METADATA_INFO_SUFFIX}", missing_ok=True
        )
    except Exception:
        pass

    _prune_session_metadata_directory(directory)
    return True


def serialize_session_metadata_item(item: SessionMetadataItem) -> Dict[str, Any]:
    source: Dict[str, Any] = {
        "storedFilename": item.filename,
    }
    if item.original_filename:
        source["originalFilename"] = item.original_filename
    if item.uploaded_at:
        source["uploadedAt"] = item.uploaded_at
    if item.mtime is not None:
        source["modifiedAt"] = datetime.fromtimestamp(item.mtime, timezone.utc).isoformat()

    payload: Dict[str, Any] = {
        "entry": item.payload,
        "source": source,
    }
    if item.legal_header:
        payload["legalHeader"] = item.legal_header

    return payload


class MetadataDownloadError(Exception):
    """Raised when the FIDO MDS metadata cannot be downloaded."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        retry_after: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def _parse_http_datetime(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parsing of an HTTP date header into an aware datetime."""

    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def _format_last_modified(header: Optional[str]) -> Optional[str]:
    """Convert an HTTP Last-Modified header to an ISO formatted string."""

    if not header:
        return None

    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header

    return parsed.isoformat()


def format_last_modified_header(header: Optional[str]) -> Optional[str]:
    """Public helper for converting HTTP Last-Modified headers to ISO format."""

    return _format_last_modified(header)


def _clean_metadata_cache_value(value: Any) -> Optional[str]:
    """Return a trimmed string value from cached metadata state if present."""

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def load_metadata_cache_entry() -> Dict[str, Optional[str]]:
    """Load cached metadata headers used for conditional download requests."""

    try:
        with open(MDS_METADATA_CACHE_PATH, "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(cached, dict):
        return {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = _format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _store_metadata_cache_entry(
    *,
    last_modified_header: Optional[str],
    last_modified_iso: Optional[str],
    etag: Optional[str],
) -> None:
    """Persist cached metadata download headers for future requests."""

    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        os.makedirs(os.path.dirname(MDS_METADATA_CACHE_PATH), exist_ok=True)
        with open(MDS_METADATA_CACHE_PATH, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, indent=2, sort_keys=True)
            cache_file.write("\n")
    except OSError:
        pass


def store_metadata_cache_entry(
    *,
    last_modified_header: Optional[str],
    last_modified_iso: Optional[str],
    etag: Optional[str],
) -> None:
    """Persist cached metadata headers for the packaged snapshot."""

    _store_metadata_cache_entry(
        last_modified_header=last_modified_header,
        last_modified_iso=last_modified_iso,
        etag=etag,
    )


def download_metadata_blob(
    source_url: str = MDS_METADATA_URL,
    destination: str = MDS_METADATA_PATH,
) -> Tuple[bool, int, Optional[str]]:
    """Fetch the FIDO MDS metadata BLOB and store it locally.

    Runtime downloads are no longer supported. The packaged snapshot is
    refreshed exclusively by the CI workflow that invokes
    ``scripts/update_mds_snapshot.py``.
    """

    raise RuntimeError(
        "Runtime metadata downloads are disabled; use the CI snapshot updater instead."
    )


def load_cached_metadata_snapshot() -> bool:
    """Warm in-memory caches from the stored MDS metadata when available."""

    metadata, _ = _load_base_metadata()
    return metadata is not None


def _load_base_metadata() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    global _base_metadata_cache, _base_metadata_mtime, _base_metadata_source
    global _base_metadata_trust_verified, _base_metadata_entry_ids

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _base_metadata_cache is not None
        and _base_metadata_source == "verified"
        and _base_metadata_mtime == verified_mtime
    ):
        return _base_metadata_cache, verified_mtime

    metadata, fallback_mtime = _load_verified_metadata_fallback()

    if metadata is not None:
        _base_metadata_entry_ids = {id(entry) for entry in metadata.entries}
        _base_metadata_trust_verified = True
        _base_metadata_source = "verified"
    else:
        _base_metadata_entry_ids = set()
        _base_metadata_trust_verified = None
        _base_metadata_source = None

    _base_metadata_cache = metadata
    _base_metadata_mtime = fallback_mtime
    return metadata, fallback_mtime


def _load_verified_metadata_fallback() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    """Load the bundled verified metadata snapshot shipped with the application."""

    try:
        fallback_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        fallback_mtime = None

    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except FileNotFoundError:
        return None, fallback_mtime
    except (OSError, json.JSONDecodeError) as exc:
        app.logger.warning(
            "Unable to load verified metadata fallback %s: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime

    try:
        return MetadataBlobPayload.from_dict(payload), fallback_mtime
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.warning(
            "Verified metadata fallback %s is invalid: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime


def _load_verified_metadata_payload() -> Optional[Dict[str, Any]]:
    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def _load_base_explorer_snapshot() -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[Optional[float], Optional[float]]]]:
    global _base_explorer_snapshot_cache, _base_explorer_snapshot_mtime

    try:
        explorer_mtime = os.path.getmtime(MDS_EXPLORER_PATH)
    except OSError:
        explorer_mtime = None

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    cache_marker = (explorer_mtime, verified_mtime)
    if (
        _base_explorer_snapshot_cache is not None
        and _base_explorer_snapshot_mtime == cache_marker
    ):
        return _base_explorer_snapshot_cache, cache_marker

    snapshot: Optional[Dict[str, Any]] = None

    if explorer_mtime is not None and (verified_mtime is None or explorer_mtime >= verified_mtime):
        try:
            with open(MDS_EXPLORER_PATH, "r", encoding="utf-8") as explorer_file:
                loaded = json.load(explorer_file)
        except (OSError, json.JSONDecodeError):
            loaded = None
        if isinstance(loaded, dict):
            snapshot = loaded

    if snapshot is None:
        payload = _load_verified_metadata_payload()
        if payload is not None:
            snapshot = build_explorer_snapshot(payload, load_metadata_cache_entry())

    _base_explorer_snapshot_cache = snapshot
    _base_explorer_snapshot_mtime = cache_marker
    return snapshot, cache_marker


def _load_base_full_snapshot() -> Tuple[Optional[Dict[str, Any]], Optional[float]]:
    global _base_full_snapshot_cache, _base_full_snapshot_mtime

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _base_full_snapshot_cache is not None
        and _base_full_snapshot_mtime == verified_mtime
    ):
        return _base_full_snapshot_cache, verified_mtime

    snapshot: Optional[Dict[str, Any]] = None
    payload = _load_verified_metadata_payload()
    if payload is not None:
        snapshot = build_bootstrap_snapshot(payload, load_metadata_cache_entry())

    _base_full_snapshot_cache = snapshot
    _base_full_snapshot_mtime = verified_mtime
    return snapshot, verified_mtime


def load_packaged_explorer_summary() -> Dict[str, Any]:
    snapshot, _ = _load_base_explorer_snapshot()
    if snapshot and isinstance(snapshot.get("meta"), Mapping):
        return dict(snapshot["meta"])

    payload = _load_verified_metadata_payload()
    if payload is None:
        return {}

    return build_explorer_snapshot(payload, load_metadata_cache_entry()).get("meta", {})


def _build_session_snapshot_entry(
    item: SessionMetadataItem,
    *,
    index: int,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> Optional[Dict[str, Any]]:
    payload = item.payload
    if not isinstance(payload, Mapping):
        return None

    return build_explorer_entry(
        payload,
        index=index,
        source="session",
        trust_anchor_status=False,
        snapshot_meta={
            "generatedAt": item.uploaded_at,
            "fetchedAt": item.uploaded_at,
        },
        include_detail=include_detail,
        include_raw_entry=include_raw_entry,
        compact_detail=compact_detail,
        source_info=_session_item_source_info(item),
    )


def _session_item_source_info(item: SessionMetadataItem) -> Dict[str, Any]:
    info: Dict[str, Any] = {"storedFilename": item.filename}
    if item.original_filename:
        info["originalFilename"] = item.original_filename
    if item.uploaded_at:
        info["uploadedAt"] = item.uploaded_at
    if item.mtime is not None:
        info["modifiedAt"] = datetime.fromtimestamp(item.mtime, timezone.utc).isoformat()
    return info


def _entry_matches_lookup(
    entry_payload: Mapping[str, Any],
    *,
    entry_id: Optional[str] = None,
    aaguid: Optional[str] = None,
    aaid: Optional[str] = None,
) -> bool:
    if entry_id:
        return build_entry_id(entry_payload) == entry_id

    metadata = entry_payload.get("metadataStatement")
    if not isinstance(metadata, Mapping):
        metadata = {}

    if aaguid:
        lookup_key = normalise_aaguid_key(aaguid)
        if not lookup_key:
            return False
        return (
            normalise_aaguid_key(entry_payload.get("aaguid") or metadata.get("aaguid"))
            == lookup_key
        )

    if aaid:
        entry_aaid = entry_payload.get("aaid") or metadata.get("aaid")
        return isinstance(entry_aaid, str) and entry_aaid.strip() == aaid

    return False


def _compose_effective_snapshot(
    base_snapshot: Optional[Mapping[str, Any]],
    *,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> Dict[str, Any]:
    base_meta: Dict[str, Any] = {}
    base_entries: List[Dict[str, Any]] = []

    if base_snapshot:
        if isinstance(base_snapshot.get("meta"), Mapping):
            base_meta = dict(base_snapshot["meta"])
        raw_entries = base_snapshot.get("entries")
        if isinstance(raw_entries, list):
            base_entries = [dict(entry) for entry in raw_entries if isinstance(entry, Mapping)]

    session_items = list_session_metadata_items()
    custom_entries: List[Dict[str, Any]] = []
    seen_aaguids: Set[str] = set()

    for index, item in enumerate(session_items):
        custom_entry = _build_session_snapshot_entry(
            item,
            index=index,
            include_detail=include_detail,
            include_raw_entry=include_raw_entry,
            compact_detail=compact_detail,
        )
        if custom_entry is None:
            continue

        aaguid_key = normalise_aaguid_key(custom_entry.get("aaguid"))
        if aaguid_key:
            if aaguid_key in seen_aaguids:
                continue
            seen_aaguids.add(aaguid_key)
        custom_entries.append(custom_entry)

    effective_entries = custom_entries[:]
    for entry in base_entries:
        aaguid_key = normalise_aaguid_key(entry.get("aaguid"))
        if aaguid_key and aaguid_key in seen_aaguids:
            continue
        effective_entries.append(entry)

    meta = dict(base_meta)
    meta["entryCount"] = len(effective_entries)
    meta["baseEntryCount"] = len(base_entries)
    meta["customEntryCount"] = len(custom_entries)
    meta["hasCustomEntries"] = bool(custom_entries)

    return {"meta": meta, "entries": effective_entries}


def load_effective_explorer_snapshot() -> Dict[str, Any]:
    base_snapshot, _ = _load_base_explorer_snapshot()
    return _compose_effective_snapshot(base_snapshot, include_detail=False)


def load_effective_full_snapshot() -> Dict[str, Any]:
    base_snapshot, _ = _load_base_full_snapshot()
    return _compose_effective_snapshot(
        base_snapshot,
        include_detail=True,
        include_raw_entry=False,
        compact_detail=True,
    )


def resolve_effective_metadata_entry(
    *,
    entry_id: Optional[str] = None,
    aaguid: Optional[str] = None,
    aaid: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    base_summary = load_packaged_explorer_summary()
    session_items = list_session_metadata_items()
    seen_aaguids: Set[str] = set()

    for index, item in enumerate(session_items):
        payload = item.payload
        if not isinstance(payload, Mapping):
            continue
        if _entry_matches_lookup(payload, entry_id=entry_id, aaguid=aaguid, aaid=aaid):
            return build_explorer_entry(
                payload,
                index=index,
                source="session",
                trust_anchor_status=False,
                snapshot_meta={
                    "generatedAt": item.uploaded_at,
                    "fetchedAt": item.uploaded_at,
                },
                include_detail=True,
                source_info=_session_item_source_info(item),
            )

        metadata_statement = payload.get("metadataStatement")
        metadata_mapping = metadata_statement if isinstance(metadata_statement, Mapping) else {}
        aaguid_key = normalise_aaguid_key(payload.get("aaguid") or metadata_mapping.get("aaguid"))
        if aaguid_key:
            seen_aaguids.add(aaguid_key)

    base_metadata, _ = _load_base_metadata()
    if base_metadata is None:
        return None

    for index, entry in enumerate(base_metadata.entries):
        payload = dict(entry)
        metadata_statement = payload.get("metadataStatement")
        metadata_mapping = metadata_statement if isinstance(metadata_statement, Mapping) else {}
        aaguid_key = normalise_aaguid_key(payload.get("aaguid") or metadata_mapping.get("aaguid"))
        if aaguid_key and aaguid_key in seen_aaguids:
            continue
        if _entry_matches_lookup(payload, entry_id=entry_id, aaguid=aaguid, aaid=aaid):
            return build_explorer_entry(
                payload,
                index=index,
                source="packaged",
                trust_anchor_status=True,
                snapshot_meta=base_summary,
                include_detail=True,
            )

    return None


def metadata_entry_trust_anchor_status(entry: Any) -> Optional[bool]:
    """Return whether *entry* originates from a trust-anchored metadata source."""

    if entry is None or not isinstance(entry, MetadataBlobPayloadEntry):
        return None

    entry_id = id(entry)
    if entry_id in _session_metadata_entry_ids:
        return False
    if entry_id in _base_metadata_entry_ids:
        return _base_metadata_trust_verified

    return _base_metadata_trust_verified


def get_mds_verifier() -> Optional[MdsAttestationVerifier]:
    """Return an MDS attestation verifier using session metadata when available."""

    global _base_verifier_cache, _base_verifier_mtime

    base_metadata, base_mtime = _load_base_metadata()
    session_items = list_session_metadata_items()

    if not session_items:
        if base_metadata is None:
            _base_verifier_cache = None
            _base_verifier_mtime = base_mtime
            return None

        if (
            _base_verifier_cache is not None
            and _base_verifier_mtime is not None
            and _base_verifier_mtime == base_mtime
        ):
            return _base_verifier_cache

        verifier = MdsAttestationVerifier(base_metadata)
        _base_verifier_cache = verifier
        _base_verifier_mtime = base_mtime
        return verifier

    if base_metadata is None and not session_items:
        return None

    metadata = _merge_metadata(base_metadata, session_items)
    return MdsAttestationVerifier(metadata)
