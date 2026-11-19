"""A visitor's uploaded metadata statements: save, list (or read one), delete, serialise.

Each upload is stored in the visitor's namespace (``visitor_session``), with an
info file beside it: its names and time, and what its listings show of it
(``listed_uploads.stored_form``). The namespace stays when its last upload goes: the idle
sweep removes it whole.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from fido2.mds3 import MetadataBlobPayloadEntry

from .. import visitor_session
from ..storage import common as storage_common
from ..storage import session_metadata
from . import entries

# What the visitor reads when an upload would take their namespace past its quota. Each says what
# to do; the MDS page shows it as it is.
_ENTRIES_PAST = (
    "Nothing was saved: these {entries} would take this browser's uploads past the {count} "
    "metadata entries this server keeps for one visitor. Delete uploads you no longer use and try again."
)
_BYTES_PAST = (
    "Nothing was saved: these {size} of metadata would take this browser's uploads past the {limit} "
    "this server keeps for one visitor. Delete uploads you no longer use and try again."
)
# What the visitor reads, after the file's name, for one entry larger than this server keeps.
_ENTRY_PAST = "It is larger, once stored, than the {limit} this server keeps for one metadata entry."

logger = logging.getLogger(__name__)

# An upload is <uuid>.json, with its info (original name, time, listing) beside it in <uuid>.json.meta.json.
_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"


def _session_metadata_directory(
    session_id: str, *, create: bool = False, cleanup: bool = True
) -> str | None:
    if not session_id:
        return None

    normalised = storage_common.normalise_session_id(session_id)
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


def stored_json(raw_payload: Mapping[str, Any], max_bytes: int | None = None) -> bytes:
    """The bytes an uploaded entry is stored as; ``ValueError`` for one JSON cannot hold,
    or one stored in more than ``max_bytes``."""

    try:
        compact = json.dumps(raw_payload)
    except (TypeError, ValueError) as exc:
        raise entries.MetadataRefused("Metadata JSON contains unsupported types.") from exc
    # Indented, an entry is never shorter than compact: one already past the limit is neither read
    # back nor indented.
    if max_bytes is None or len(compact) <= max_bytes:
        stored = (json.dumps(json.loads(compact), indent=2, sort_keys=True) + "\n").encode("utf-8")
        if max_bytes is None or len(stored) <= max_bytes:
            return stored
    raise entries.MetadataRefused(_ENTRY_PAST.format(limit=storage_common.describe_size(max_bytes)))


def refuse_past_quota(
    session_id: str, raw_payloads: list[Mapping[str, Any]], quota: storage_common.Quota, max_entry_bytes: int
) -> None:
    """Refuse, before any is saved, entries that would take the namespace's uploads past its quota.

    Raises ``StorageQuotaExceeded``: 409 past the count of entries, 413 past their
    bytes (each upload's own file; its info file beside it is not counted). An entry
    JSON cannot hold, or one stored in more than ``max_entry_bytes``, is not counted:
    it is refused when it is saved.
    """

    sizes = []
    for raw_payload in raw_payloads:
        try:
            sizes.append(len(stored_json(raw_payload, max_entry_bytes)))
        except ValueError:
            continue
    if not sizes:
        return
    stored = [size for name, size in session_metadata.file_sizes(session_id).items() if _is_upload(name)]
    if len(stored) + len(sizes) > quota.count:
        counted = f"{len(sizes):,} metadata {'entry' if len(sizes) == 1 else 'entries'}"
        raise storage_common.StorageQuotaExceeded(409, _ENTRIES_PAST.format(entries=counted, count=f"{quota.count:,}"))
    if sum(stored) + sum(sizes) > quota.total_bytes:
        size, limit = storage_common.describe_size(sum(sizes)), storage_common.describe_size(quota.total_bytes)
        raise storage_common.StorageQuotaExceeded(413, _BYTES_PAST.format(size=size, limit=limit))


def save_session_metadata_item(
    raw_payload: Mapping[str, Any],
    *,
    original_filename: str | None = None,
    max_bytes: int | None = None,
    listed: Callable[[SessionMetadataItem], dict[str, Any]] | None = None,
) -> SessionMetadataItem:
    """Save an entry in the visitor's namespace, with its info file; with ``listed``, what it
    gives of the upload (``listed_uploads.stored_form``) is kept in the info too, with the
    entry's size, which ties it to this entry (``stored_listing``)."""

    session_id = visitor_session.ensure_id()
    # The upload marked the namespace once for all its entries (routes/mds.py).
    directory = _session_metadata_directory(session_id)

    # Its size first: an entry past it is refused before fido2 reads it. Read from the bytes
    # stored, as a listing reads it back (their keys sorted).
    json_payload = stored_json(raw_payload, max_bytes)
    entry, legal_header, payload = entries.build_metadata_entry_components(json.loads(json_payload))

    stored_filename = f"{uuid.uuid4().hex}{_SESSION_METADATA_SUFFIX}"
    info_payload: dict[str, Any] = {
        "original_filename": original_filename or None,
        "stored_filename": stored_filename,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    item = SessionMetadataItem(stored_filename, payload, legal_header, entry, mtime=None, **_info_names(info_payload))
    if listed is not None:
        # Worked out before the entry is written: one whose listing cannot be is not stored.
        info_payload = {"listed": {**listed(item), "stored_bytes": len(json_payload)}, **info_payload}

    try:
        session_metadata.write_file(
            directory,
            stored_filename,
            json_payload,
            content_type="application/json",
        )
    except Exception as exc:
        logger.error(
            "Failed to store session metadata %s: %s", stored_filename, exc
        )
        raise RuntimeError("Failed to store uploaded metadata on the server.") from exc

    # Compact, since it holds a row: its members in the order of their names, the row's in its own.
    info_json = json.dumps(info_payload, separators=(",", ":")) + "\n"
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

    return replace(item, original_filename=original_filename or None, mtime=mtime)


def _is_upload(name: str) -> bool:
    return name.endswith(_SESSION_METADATA_SUFFIX) and not name.endswith(_SESSION_METADATA_INFO_SUFFIX)


def has_items(session_id: str) -> bool:
    """Whether the namespace ``session_id`` (as ``visitor_session.current_id()`` names it)
    holds an upload; StorageReadError when its uploads cannot be listed."""

    return any(_is_upload(name) for name in session_metadata.list_files(session_id))


@dataclass(frozen=True)
class StoredUpload:
    """An upload as one listing of its namespace names it: its stored name, when it was
    written, and its version, which writing it or its info file changes (their sizes
    and times)."""

    filename: str
    mtime: float | None
    version: tuple[Any, ...]


def list_stored_uploads(session_id: str | None = None) -> tuple[str, list[StoredUpload]]:
    """The visitor's namespace ('' without one) and its uploads, by stored name, from one
    listing of it: no upload is read."""

    active_session = session_id or visitor_session.current_id()
    if not active_session:
        return "", []

    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory:
        return "", []

    visitor_session.note_activity(active_session)

    # A namespace whose uploads cannot be listed raises StorageReadError (503), never "no uploads".
    stats = session_metadata.file_stats(directory)
    return directory, [
        StoredUpload(name, stats[name][1], (stats[name], stats.get(f"{name}{_SESSION_METADATA_INFO_SUFFIX}")))
        for name in sorted(stats)
        if _is_upload(name)
    ]


def read_stored_info(namespace: str, upload: StoredUpload) -> dict[str, Any]:
    """The info file beside the upload a listing of ``namespace`` names; {} when the listing
    names none, or for one that does not read as a JSON object."""

    if upload.version[1] is None:
        return {}
    return _load_session_metadata_info(namespace, f"{upload.filename}{_SESSION_METADATA_INFO_SUFFIX}")


def stored_listing(upload: StoredUpload, info: Mapping[str, Any]) -> dict[str, Any] | None:
    """What ``info``, the upload's (``read_stored_info``), keeps for its listings when it is
    certainly this entry's: it names the entry's file, keeps its size as the listing gives it,
    and was written after it. An entry written again since keeps none: it is read instead."""

    listed = info.get("listed")
    (size, written), info_stat = upload.version
    if not isinstance(listed, dict) or info.get("stored_filename") != upload.filename or listed.get("stored_bytes") != size:
        return None
    info_written = info_stat[1] if info_stat is not None else None
    return listed if written is not None and info_written is not None and info_written >= written else None


def read_stored_upload(namespace: str, upload: StoredUpload, info: Mapping[str, Any] | None = None) -> SessionMetadataItem | None:
    """The upload a listing of ``namespace`` names (``list_stored_uploads``), with its info
    (``info``, when it was read already); None, with a warning, for one that does not read as
    a metadata entry."""

    return _read_item(namespace, upload.filename, upload.mtime, info)


def list_session_metadata_items(session_id: str | None = None) -> list[SessionMetadataItem]:
    namespace, stored = list_stored_uploads(session_id)
    items = [item for item in (read_stored_upload(namespace, upload) for upload in stored) if item is not None]
    items.sort(key=lambda item: item.mtime or 0, reverse=True)
    return items


def load_session_metadata_item(stored_filename: str, session_id: str | None = None) -> SessionMetadataItem | None:
    """The visitor's upload ``stored_filename``, or None: without a namespace, for a name
    that is no upload's, and for an upload that is not there or does not read."""

    try:
        safe_name = _validate_session_metadata_filename(stored_filename)
    except ValueError:
        return None
    active_session = session_id or visitor_session.current_id()
    if not active_session or not _is_upload(safe_name):
        return None

    directory = _session_metadata_directory(active_session, create=False, cleanup=False)
    if not directory or not session_metadata.file_exists(directory, safe_name):
        return None
    try:
        mtime = session_metadata.file_mtime(directory, safe_name)
    except Exception:
        mtime = None
    return _read_item(directory, safe_name, mtime)


def read_upload_entry(namespace: str, filename: str) -> MetadataBlobPayloadEntry | None:
    """The entry of the upload ``filename`` a listing of ``namespace`` named, read without its
    info; None, with a warning, for one that does not read as a metadata entry."""

    components = _read_components(namespace, filename)
    return components[0] if components is not None else None


def _read_components(directory: str, filename: str) -> tuple[MetadataBlobPayloadEntry, str | None, dict[str, Any]] | None:
    try:
        payload_bytes = session_metadata.read_file(directory, filename)
        raw = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else None
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        logger.warning(
            "Failed to load session metadata from %s/%s: %s", directory, filename, exc
        )
        return None

    try:
        return entries.build_metadata_entry_components(raw)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "Failed to parse session metadata entry from %s/%s: %s",
            directory,
            filename,
            exc,
        )
        return None


def _read_item(
    directory: str, filename: str, mtime: float | None, info: Mapping[str, Any] | None = None
) -> SessionMetadataItem | None:
    """The upload ``filename`` of the namespace ``directory``, written at ``mtime``, with its
    info (read here without ``info``); None, with a warning, for one that does not read as a
    metadata entry."""

    components = _read_components(directory, filename)
    if components is None:
        return None
    entry, legal_header, payload = components

    if info is None:
        info = _load_session_metadata_info(directory, f"{filename}{_SESSION_METADATA_INFO_SUFFIX}")
    return SessionMetadataItem(filename, payload, legal_header, entry, mtime=mtime, **_info_names(info))


def _info_names(info: Mapping[str, Any]) -> dict[str, str | None]:
    """When an upload was made and the name it was uploaded as, as its info file gives them."""

    raw_uploaded_at = info.get("uploaded_at")
    raw_original_name = info.get("original_filename")
    return {
        "uploaded_at": raw_uploaded_at.strip() if isinstance(raw_uploaded_at, str) else None,
        "original_filename": (
            raw_original_name.strip() if isinstance(raw_original_name, str) and raw_original_name.strip() else None
        ),
    }


def delete_session_metadata_item(
    stored_filename: str, session_id: str | None = None
) -> bool:
    safe_name = _validate_session_metadata_filename(stored_filename)
    active_session = session_id or visitor_session.current_id()
    if not active_session:
        return False

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

    return True


def serialize_session_metadata_item(item: SessionMetadataItem) -> dict[str, Any]:
    """An upload as Manage Metadata lists it, and no more: the name it is stored under
    (which a delete names), the name it was uploaded as and when, and whether it holds
    a legal header; the explorer shows its entry (``mds.effective``)."""

    source: dict[str, Any] = {
        "storedFilename": item.filename,
    }
    if item.original_filename:
        source["originalFilename"] = item.original_filename
    if item.uploaded_at:
        source["uploadedAt"] = item.uploaded_at

    return {"source": source, "hasLegalHeader": bool(item.legal_header)}
