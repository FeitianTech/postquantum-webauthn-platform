"""Session metadata item dataclass and CRUD helpers."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class SessionMetadataItem:
    filename: str
    payload: Dict[str, Any]
    legal_header: Optional[str]
    entry: MetadataBlobPayloadEntry
    uploaded_at: Optional[str]
    original_filename: Optional[str]
    mtime: Optional[float]


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
