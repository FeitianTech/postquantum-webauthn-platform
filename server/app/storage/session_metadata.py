"""A visitor's uploads store, and the namespace each visitor's stores share: its
last-access marker, the listing of namespaces, and their removal, whole, by the
idle sweep (``visitor_session``).

On Cloud Storage a namespace is ``user-data/<namespace>/``, every store's objects
under it. Locally each store keeps the namespace's folder under its own root
(``config.paths.LOCAL_STORES``): the namespace is the three folders, and the
uploads store's holds its marker.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time

from ..config.paths import LOCAL_STORES, METADATA_STORE, store_dir
from . import common
from .cloud import (
    blob_exists,
    blob_updated_timestamp,
    build_blob_name,
    delete_blob,
    download_bytes,
    list_blob_names,
    list_blob_stats,
    list_prefixes,
    upload_bytes,
)

logger = logging.getLogger(__name__)

__all__ = [
    "delete_file",
    "delete_session",
    "ensure_session",
    "file_exists",
    "file_mtime",
    "file_sizes",
    "file_stats",
    "list_files",
    "list_sessions",
    "read_file",
    "resolve_last_access",
    "session_is_empty",
    "touch_last_access",
    "write_file",
]

_METADATA_SUBDIR = "metadata"
_LAST_ACCESS_BLOB = ".last-access"




def session_metadata_dir() -> str:
    """Where the visitors' uploads are kept locally (``FIDO_SERVER_SESSION_METADATA_DIR``)."""

    return store_dir(*METADATA_STORE)



def _user_root_prefix(session_id: str) -> str:
    return common.session_root_prefix(session_id)


def _metadata_prefix(session_id: str) -> str:
    return common.session_prefix(session_id, _METADATA_SUBDIR)


def _last_access_blob(session_id: str) -> str:
    root = _user_root_prefix(session_id)
    return build_blob_name(_LAST_ACCESS_BLOB, prefix=root)


def _session_blob(session_id: str, name: str) -> str:
    cleaned = name.strip("/")
    if not cleaned:
        raise ValueError("Invalid metadata filename")
    return f"{_metadata_prefix(session_id)}/{cleaned}"


def _base_prefix() -> str:
    return f"{common.USER_FOLDER_PREFIX}/"


def _normalise_local_session_id(session_id: str) -> str:
    normalised = common.normalise_session_id(session_id)
    if normalised is None:
        raise ValueError("Session identifier is invalid")
    return normalised


def _local_session_directory(session_id: str, *, create: bool = False) -> str | None:
    try:
        normalised = _normalise_local_session_id(session_id)
    except ValueError:
        return None

    directory = os.path.join(session_metadata_dir(), normalised)

    if create:
        try:
            common.make_store_directory(session_metadata_dir(), directory)
        except OSError as exc:
            logger.error("Failed to prepare session metadata directory %s: %s", directory, exc)
            raise
        _local_touch_last_access(directory)

    return directory


def _local_touch_last_access(directory: str) -> None:
    marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
    try:
        os.makedirs(os.path.dirname(marker_path), exist_ok=True)
        with open(marker_path, "a", encoding="utf-8"):
            os.utime(marker_path, None)
    except OSError:
        pass


def _local_namespace_folders(session_id: str) -> list[str]:
    """The namespace's folder in each local store, those that exist; none for a name that is no namespace."""

    try:
        normalised = _normalise_local_session_id(session_id)
    except ValueError:
        return []
    folders = (os.path.join(store_dir(*store), normalised) for store in LOCAL_STORES)
    return [folder for folder in folders if os.path.isdir(folder)]


def _local_resolve_last_access(directory: str) -> float | None:
    """The namespace whose uploads folder is ``directory``: when it was last used."""

    marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
    try:
        return os.path.getmtime(marker_path)
    except OSError:
        pass

    # Else the newest entry in the namespace's folders, else the newest folder.
    # An entry or a folder that goes while it is read leaves the time unknown:
    # the idle sweep keeps the namespace until it looks again.
    folders = _local_namespace_folders(os.path.basename(directory))
    if not folders:
        return None
    try:
        times = []
        for folder in folders:
            with os.scandir(folder) as entries:
                times.extend(entry.stat(follow_symlinks=False).st_mtime for entry in entries)
        return max(times) if times else max(os.path.getmtime(folder) for folder in folders)
    except OSError:
        return None


def _local_note_activity(session_id: str) -> None:
    # Idle sessions are swept by server.app.visitor_session, on both backends.
    directory = _local_session_directory(session_id)
    if directory and os.path.isdir(directory):
        _local_touch_last_access(directory)


def ensure_session(session_id: str) -> None:
    if common.using_gcs():
        touch_last_access(session_id)
    else:
        _local_session_directory(session_id, create=True)


def list_sessions() -> list[str]:
    if common.using_gcs():
        prefix = _base_prefix()
        seen = set()
        try:
            # One entry per session folder, not every object in every session.
            # A flat object beside the folders is no session.
            for folder in list_prefixes(prefix):
                session_component = folder[len(prefix) :].strip("/").strip()
                if session_component:
                    seen.add(session_component)
        except Exception as exc:
            logger.warning("Unable to list session metadata blobs: %s", exc)
        return sorted(seen)

    # Every store's namespaces: one that has only credentials or artifacts is one too.
    sessions: set[str] = set()
    for store in LOCAL_STORES:
        root = store_dir(*store)
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        sessions.update(entry for entry in entries if not entry.startswith(".") and os.path.isdir(os.path.join(root, entry)))
    return sorted(sessions)


def touch_last_access(session_id: str, *, timestamp: float | None = None) -> None:
    if common.using_gcs():
        marker_name = _last_access_blob(session_id)
        marker_value = json.dumps({"timestamp": timestamp or time.time()}).encode("utf-8")
        upload_bytes(marker_name, marker_value, content_type="application/json")
        return

    directory = _local_session_directory(session_id, create=True)
    if directory is None:
        return
    if timestamp:
        marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
        try:
            os.makedirs(os.path.dirname(marker_path), exist_ok=True)
            with open(marker_path, "a", encoding="utf-8"):
                os.utime(marker_path, (timestamp, timestamp))
        except OSError:
            pass
    else:
        _local_touch_last_access(directory)


def resolve_last_access(session_id: str) -> float | None:
    """When the namespace was last used: its marker's time, else its newest object's or file's
    (one written but never marked, as a touch that failed leaves it); None when it holds nothing."""

    if common.using_gcs():
        marker_name = _last_access_blob(session_id)
        payload = download_bytes(marker_name)
        if payload:
            try:
                data = json.loads(payload.decode("utf-8"))
                if isinstance(data, dict) and isinstance(data.get("timestamp"), (int, float)):
                    return float(data["timestamp"])
            except Exception:
                pass
        marker_time = blob_updated_timestamp(marker_name)
        if marker_time is not None:
            return marker_time
        times = [stat.updated for stat in list_blob_stats(_user_root_prefix(session_id) + "/") if stat.updated is not None]
        return max(times) if times else None

    directory = _local_session_directory(session_id)
    if not directory:
        return None
    return _local_resolve_last_access(directory)


def list_files(session_id: str) -> list[str]:
    """The namespace's uploaded files, by name; raises ``StorageReadError`` when
    the store cannot be listed, never answering with fewer files."""

    if common.using_gcs():
        prefix = _metadata_prefix(session_id) + "/"
        names: list[str] = []
        try:
            for blob_name in list_blob_names(prefix):
                remainder = blob_name[len(prefix) :]
                if not remainder:
                    continue
                if remainder.endswith("/"):
                    continue
                if remainder == _LAST_ACCESS_BLOB:
                    continue
                names.append(remainder)
        except Exception as exc:
            raise common.StorageReadError(f"the uploads of {session_id} could not be listed") from exc
        return sorted(names)

    directory = _local_session_directory(session_id)
    if not directory:
        return []

    try:
        entries = os.listdir(directory)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise common.StorageReadError(f"the uploads of {session_id} could not be listed") from exc

    names: list[str] = []
    for entry in entries:
        if entry == _LAST_ACCESS_BLOB or entry.startswith("."):
            continue
        path = os.path.join(directory, entry)
        if os.path.isfile(path):
            names.append(entry)
    return sorted(names)


def file_stats(session_id: str) -> dict[str, tuple[int, float | None]]:
    """The namespace's uploaded files, by name, each with its size in bytes and the time
    it was last written (epoch seconds, as ``file_mtime`` reads it): what ``list_files``
    names, from one listing. Raises ``StorageReadError`` when the store cannot be listed,
    never answering with fewer files."""

    if common.using_gcs():
        prefix = _metadata_prefix(session_id) + "/"
        try:
            stats = list_blob_stats(prefix)
        except Exception as exc:
            raise common.StorageReadError(f"the uploads of {session_id} could not be listed") from exc
        named = {stat.name[len(prefix) :]: (stat.size, stat.updated) for stat in stats}
        return {name: stat for name, stat in named.items() if name and not name.endswith("/") and name != _LAST_ACCESS_BLOB}

    directory = _local_session_directory(session_id)
    if not directory:
        return {}
    try:
        with os.scandir(directory) as entries:
            return {
                entry.name: (entry.stat().st_size, entry.stat().st_mtime)
                for entry in entries
                if not entry.name.startswith(".") and entry.is_file()
            }
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise common.StorageReadError(f"the uploads of {session_id} could not be listed") from exc


def file_sizes(session_id: str) -> dict[str, int]:
    """The namespace's uploaded files, by name, each with its size in bytes (``file_stats``)."""

    return {name: size for name, (size, _written) in file_stats(session_id).items()}


def read_file(session_id: str, name: str) -> bytes | None:
    if common.using_gcs():
        blob_name = _session_blob(session_id, name)
        return download_bytes(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return None

    path = os.path.join(directory, name)
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def write_file(session_id: str, name: str, data: bytes, *, content_type: str | None = None) -> None:
    if common.using_gcs():
        blob_name = _session_blob(session_id, name)
        upload_bytes(blob_name, data, content_type=content_type)
        touch_last_access(session_id)
        return

    directory = _local_session_directory(session_id, create=True)
    if not directory:
        raise ValueError("Invalid session identifier")

    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    _local_note_activity(session_id)


def delete_file(session_id: str, name: str, *, missing_ok: bool = True) -> None:
    if common.using_gcs():
        blob_name = _session_blob(session_id, name)
        delete_blob(blob_name, missing_ok=missing_ok)
        touch_last_access(session_id)
        return

    directory = _local_session_directory(session_id)
    if not directory:
        return

    path = os.path.join(directory, name)
    try:
        os.remove(path)
    except FileNotFoundError:
        if not missing_ok:
            raise
    except OSError:
        if not missing_ok:
            raise
    _local_note_activity(session_id)


def file_mtime(session_id: str, name: str) -> float | None:
    if common.using_gcs():
        blob_name = _session_blob(session_id, name)
        return blob_updated_timestamp(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return None

    path = os.path.join(directory, name)
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def session_is_empty(session_id: str) -> bool:
    return not list_files(session_id)


def delete_session(session_id: str) -> None:
    """Remove the namespace whole: every object under it on Cloud Storage, its folder
    in each local store (``config.paths.LOCAL_STORES``) on disk."""

    if common.using_gcs():
        prefix = _user_root_prefix(session_id) + "/"
        to_delete: list[str] = []
        try:
            for blob_name in list_blob_names(prefix):
                to_delete.append(blob_name)
        except Exception as exc:
            logger.warning("Unable to enumerate metadata for deletion under %s: %s", prefix, exc)
        for blob_name in to_delete:
            delete_blob(blob_name, missing_ok=True)
        return

    for folder in _local_namespace_folders(session_id):
        try:
            shutil.rmtree(folder)
        except OSError as exc:
            logger.warning("Failed to remove metadata session %s: %s", folder, exc)


def file_exists(session_id: str, name: str) -> bool:
    if common.using_gcs():
        blob_name = _session_blob(session_id, name)
        return blob_exists(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return False
    return os.path.isfile(os.path.join(directory, name))
