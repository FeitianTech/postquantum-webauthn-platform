"""A visitor's uploaded metadata statements: save, list, delete, serialise.

Each upload is stored in the visitor's namespace (``visitor_session``), with an
info file beside it; the namespace goes when the last upload does.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fido2.mds3 import MetadataBlobPayloadEntry

from .. import visitor_session
from ..storage import session_metadata
from . import entries

logger = logging.getLogger(__name__)

# An upload is <uuid>.json, with its info (original name, time) beside it in <uuid>.json.meta.json.
_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"


def _session_metadata_directory(
    session_id: str, *, create: bool = False, cleanup: bool = True
) -> str | None:
    if not session_id:
        return None

    normalised = visitor_session.normalise_id(session_id)
    if not normalised:
        return None

    if create:
        try:
            session_metadata.ensure_session(normalised)
        except Exception as exc:
            logger.error(
                "Failed to prepare session metadata storage for %s: %s", normalised, exc
            )
            raise
    if cleanup:
        visitor_session.schedule_cleanup()
    return normalised


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
    session_id = visitor_session.ensure_id()
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
        logger.error(
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
        logger.warning(
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
    active_session = session_id or visitor_session.current_id()
    if not active_session:
        return []

    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        return []

    visitor_session.note_activity(active_session)

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
            logger.warning(
                "Failed to load session metadata from %s/%s: %s", directory, filename, exc
            )
            continue

        try:
            entry, legal_header, payload = entries.build_metadata_entry_components(raw)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
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
    active_session = session_id or visitor_session.current_id()
    if not active_session:
        raise ValueError("No active metadata session.")

    safe_name = _validate_session_metadata_filename(stored_filename)
    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        return False

    visitor_session.note_activity(active_session)

    try:
        exists = session_metadata.file_exists(directory, safe_name)
    except Exception:
        exists = False

    if not exists:
        return False

    try:
        session_metadata.delete_file(directory, safe_name, missing_ok=False)
    except Exception as exc:
        logger.error(
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
