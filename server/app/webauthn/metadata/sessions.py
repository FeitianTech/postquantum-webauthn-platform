"""Environment and cleanup interval helpers for metadata runtime."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import after_this_request, g, has_request_context, request, session
from itsdangerous import BadSignature, URLSafeTimedSerializer

from fido2.mds3 import MetadataBlobPayloadEntry

from ...config import app
from ...env_flags import parse_env_flag
from ...storage import session_metadata
from . import entries
from . import state as _state
from .state import (
    _SESSION_METADATA_CLEANUP_ASYNC_ENV,
    _SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV,
    _SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV,
    _SESSION_METADATA_COOKIE_MAX_AGE,
    _SESSION_METADATA_COOKIE_NAME,
    _SESSION_METADATA_INACTIVE_AGE,
    _SESSION_METADATA_INFO_SUFFIX,
    _SESSION_METADATA_SESSION_KEY,
    _SESSION_METADATA_SUFFIX,
    _SESSION_METADATA_TOUCH_KEY,
    _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS,
    _SESSION_METADATA_TOUCH_THROTTLE_ENV,
)


def _env_flag(name: str) -> bool | None:
    return parse_env_flag(name)


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


def _cleanup_async_enabled() -> bool:
    explicit = _env_flag(_SESSION_METADATA_CLEANUP_ASYNC_ENV)
    if explicit is None:
        return True
    return explicit


_SESSION_METADATA_CLEANUP_INTERVAL = _resolve_cleanup_interval()


def _touch_session_last_access(session_id: str) -> None:
    try:
        session_metadata.touch_last_access(session_id)
    except Exception:
        pass


def _resolve_session_last_access(session_id: str) -> float | None:
    try:
        return session_metadata.resolve_last_access(session_id)
    except Exception:
        return None


def _maybe_cleanup_inactive_sessions(now: float | None = None) -> None:
    current_time = now or time.time()
    with _state._session_cleanup_lock:
        if current_time - _state._session_metadata_last_cleanup < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds():
            return
        _state._session_metadata_last_cleanup = current_time

    cutoff = current_time - _SESSION_METADATA_INACTIVE_AGE.total_seconds()

    try:
        sessions = session_metadata.list_sessions()
    except Exception:
        return

    for session_id in sessions:
        last_access = _resolve_session_last_access(session_id)
        if last_access is None or last_access >= cutoff:
            continue

        try:
            session_metadata.delete_session(session_id)
        except Exception as exc:
            app.logger.warning(
                "Failed to remove inactive metadata session %s: %s", session_id, exc
            )


def _run_inactive_session_cleanup_worker() -> None:
    while True:
        try:
            _maybe_cleanup_inactive_sessions()
        except Exception as exc:  # pragma: no cover - defensive logging
            app.logger.warning(
                "Unexpected failure while cleaning inactive metadata sessions: %s",
                exc,
                exc_info=True,
            )

        with _state._session_cleanup_lock:
            if _state._session_cleanup_pending:
                _state._session_cleanup_pending = False
                continue

            _state._session_cleanup_worker = None
            return


def _schedule_inactive_session_cleanup() -> None:
    current_time = time.time()
    if (
        current_time - _state._session_metadata_last_cleanup
        < _SESSION_METADATA_CLEANUP_INTERVAL.total_seconds()
    ):
        return

    if not _cleanup_async_enabled():
        _maybe_cleanup_inactive_sessions(now=current_time)
        return

    worker: threading.Thread | None = None

    with _state._session_cleanup_lock:
        if _state._session_cleanup_worker is not None and _state._session_cleanup_worker.is_alive():
            _state._session_cleanup_pending = True
            return

        worker = threading.Thread(
            target=_run_inactive_session_cleanup_worker,
            name="session-metadata-cleanup",
            daemon=True,
        )
        _state._session_cleanup_worker = worker

    try:
        worker.start()
    except RuntimeError:  # pragma: no cover - defensive fallback
        with _state._session_cleanup_lock:
            if _state._session_cleanup_worker is worker:
                _state._session_cleanup_worker = None
                _state._session_cleanup_pending = False
        _maybe_cleanup_inactive_sessions(now=current_time)


def _normalise_session_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


# Salt for the metadata-session recovery cookie; the key is ``app.secret_key``.


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

    # The recovery cookie is client storage.  Handing back a bare namespace name
    # lets anyone who can set a cookie point themselves at another visitor's
    # namespace, so the value that leaves the server is signed with the
    # application secret and the signature is re-checked on the way back in.
    secret = app.secret_key
    if not secret:
        return

    sealed = URLSafeTimedSerializer(
        secret, salt="fido.mds.session-cookie.v1"
    ).dumps(normalised)

    g._session_metadata_cookie = normalised

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            _SESSION_METADATA_COOKIE_NAME,
            sealed,
            max_age=_SESSION_METADATA_COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path=cookie_path,
        )
        return response


def _get_metadata_session_id(*, create: bool = False) -> str | None:
    if not has_request_context():
        return None

    # The signed Flask session is authoritative.  It is authenticated with the
    # application secret, so a caller cannot point it at somebody else's
    # namespace.
    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str):
        identifier = _normalise_session_identifier(existing)
        if identifier:
            session[_SESSION_METADATA_SESSION_KEY] = identifier
            _schedule_session_cookie(identifier)
            return identifier

    # Otherwise fall back to the long-lived recovery cookie, so a returning
    # visitor keeps their namespace after the (much shorter lived) Flask session
    # has expired.  Only a cookie this server signed is honoured; a forged or
    # replayed-from-elsewhere value is ignored and a fresh namespace is minted
    # instead, which is what stops one caller reading another's stored metadata
    # and credential artifacts.
    cookie_identifier = None
    raw_cookie = request.cookies.get(_SESSION_METADATA_COOKIE_NAME)
    secret = app.secret_key
    if isinstance(raw_cookie, str) and raw_cookie and secret:
        try:
            unsealed = URLSafeTimedSerializer(
                secret, salt="fido.mds.session-cookie.v1"
            ).loads(raw_cookie, max_age=_SESSION_METADATA_COOKIE_MAX_AGE)
        except BadSignature:
            # Also covers SignatureExpired / BadTimeSignature.
            unsealed = None
        except Exception:
            unsealed = None
        cookie_identifier = _normalise_session_identifier(unsealed)

    if cookie_identifier:
        session[_SESSION_METADATA_SESSION_KEY] = cookie_identifier
        _schedule_session_cookie(cookie_identifier)
        return cookie_identifier

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
    # A brand-new session has nothing stored yet, so it does not need a
    # last-access marker until it writes data (writes refresh it themselves).
    g._mds_session_new = identifier
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
) -> str | None:
    if not session_id:
        return None

    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return None

    if create:
        try:
            session_metadata.ensure_session(normalised)
        except Exception as exc:
            app.logger.error(
                "Failed to prepare session metadata storage for %s: %s", normalised, exc
            )
            raise
    if cleanup:
        _schedule_inactive_session_cleanup()
    return normalised


def _note_session_activity(session_id: str, *, directory: str | None = None) -> None:
    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return

    if has_request_context():
        # Refreshing the marker is a storage write, so do it at most once per
        # request and at most once per throttle window per session.
        if getattr(g, "_mds_session_touched", None) == normalised:
            return
        g._mds_session_touched = normalised

        now = time.time()
        if getattr(g, "_mds_session_new", None) == normalised:
            session[_SESSION_METADATA_TOUCH_KEY] = now
            _schedule_inactive_session_cleanup()
            return

        raw_throttle = os.environ.get(_SESSION_METADATA_TOUCH_THROTTLE_ENV)
        try:
            throttle = (
                float(raw_throttle)
                if raw_throttle
                else _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS
            )
        except ValueError:
            throttle = _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS

        last_touch = session.get(_SESSION_METADATA_TOUCH_KEY)
        if isinstance(last_touch, (int, float)) and 0 <= now - last_touch < throttle:
            _schedule_inactive_session_cleanup()
            return
        session[_SESSION_METADATA_TOUCH_KEY] = now

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


@dataclass(frozen=True)
class SessionMetadataItem:
    filename: str
    payload: dict[str, Any]
    legal_header: str | None
    entry: MetadataBlobPayloadEntry
    uploaded_at: str | None
    original_filename: str | None
    mtime: float | None


def _prune_session_metadata_directory(session_id: str) -> None:
    try:
        session_metadata.prune_session(session_id)
    except Exception:
        pass


def _load_session_metadata_info(session_id: str, filename: str) -> dict[str, Any]:
    try:
        payload_bytes = session_metadata.read_file(session_id, filename)
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


def save_session_metadata_item(
    raw_payload: Mapping[str, Any],
    *,
    original_filename: str | None = None,
) -> SessionMetadataItem:
    session_id = ensure_metadata_session_id()
    directory = _session_metadata_directory(session_id, create=True)
    if not directory:
        raise RuntimeError("Unable to resolve session metadata storage path.")

    entry, legal_header, payload = entries.build_metadata_entry_components(raw_payload)

    try:
        serialisable_payload = json.loads(json.dumps(raw_payload))
    except (TypeError, ValueError) as exc:
        raise ValueError("Metadata JSON contains unsupported types.") from exc

    stored_filename = f"{uuid.uuid4().hex}{_SESSION_METADATA_SUFFIX}"
    json_payload = json.dumps(serialisable_payload, indent=2, sort_keys=True) + "\n"

    try:
        session_metadata.write_file(
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
        session_metadata.write_file(
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
        mtime = session_metadata.file_mtime(directory, stored_filename)
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


def list_session_metadata_items(session_id: str | None = None) -> list[SessionMetadataItem]:
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        return []

    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        return []

    _note_session_activity(active_session, directory=directory)

    try:
        filenames = [
            name
            for name in session_metadata.list_files(directory)
            if name.endswith(_SESSION_METADATA_SUFFIX)
            and not name.endswith(_SESSION_METADATA_INFO_SUFFIX)
        ]
    except Exception:
        return []

    items: list[SessionMetadataItem] = []
    for filename in sorted(filenames):
        try:
            payload_bytes = session_metadata.read_file(directory, filename)
            raw = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else None
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            app.logger.warning(
                "Failed to load session metadata from %s/%s: %s", directory, filename, exc
            )
            continue

        try:
            entry, legal_header, payload = entries.build_metadata_entry_components(raw)
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
            mtime = session_metadata.file_mtime(directory, filename)
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
    return items


def delete_session_metadata_item(
    stored_filename: str, session_id: str | None = None
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
        exists = session_metadata.file_exists(directory, safe_name)
    except Exception:
        exists = False

    if not exists:
        return False

    try:
        session_metadata.delete_file(directory, safe_name, missing_ok=False)
    except Exception as exc:
        app.logger.error(
            "Failed to delete session metadata %s/%s: %s", directory, safe_name, exc
        )
        raise RuntimeError("Failed to delete the uploaded metadata file.") from exc

    try:
        session_metadata.delete_file(
            directory, f"{safe_name}{_SESSION_METADATA_INFO_SUFFIX}", missing_ok=True
        )
    except Exception:
        pass

    _prune_session_metadata_directory(directory)
    return True


def serialize_session_metadata_item(item: SessionMetadataItem) -> dict[str, Any]:
    source: dict[str, Any] = {
        "storedFilename": item.filename,
    }
    if item.original_filename:
        source["originalFilename"] = item.original_filename
    if item.uploaded_at:
        source["uploadedAt"] = item.uploaded_at
    if item.mtime is not None:
        source["modifiedAt"] = datetime.fromtimestamp(item.mtime, timezone.utc).isoformat()

    payload: dict[str, Any] = {
        "entry": item.payload,
        "source": source,
    }
    if item.legal_header:
        payload["legalHeader"] = item.legal_header

    return payload
