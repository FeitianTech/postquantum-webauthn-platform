"""The packaged snapshot's files, loaded into the caches between requests.

``CACHE`` holds what was read, keyed by the modification times of the files it
came from, so a snapshot swapped in (written whole, metas last) is read again on
the next request. It is the one copy per process: gunicorn runs one worker.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fido2.mds3 import MdsAttestationVerifier

from . import explorer_files as mds_explorer_files
from . import files as mds_files
from .build import build_bootstrap_snapshot, build_explorer_snapshot

logger = logging.getLogger(__name__)


@dataclass
class SnapshotCache:
    """The snapshot as last read: each value with the file modification times it was read at."""

    # The verified payload's entries as its JSON holds them, for the file version read.
    raw_entries: list[Any] | None = None
    raw_entries_mtime: float | None = None
    # The explorer's and the full snapshot, keyed by the mtimes of their four files.
    explorer: dict[str, Any] | None = None
    explorer_mtime: tuple[float | None, ...] | None = None
    full: dict[str, Any] | None = None
    full_mtime: tuple[float | None, ...] | None = None
    # The browsers' files derived from the full snapshot, keyed like it.
    explorer_files: mds_explorer_files.ExplorerFiles | None = None
    explorer_files_mtime: tuple[float | None, ...] | None = None
    # The verifier over the verified entries (mds/verifier.py), for the list it was built from.
    verifier: MdsAttestationVerifier | None = None
    metadata_lock: threading.RLock = field(default_factory=threading.RLock)
    explorer_lock: threading.RLock = field(default_factory=threading.RLock)
    full_lock: threading.RLock = field(default_factory=threading.RLock)
    explorer_files_lock: threading.RLock = field(default_factory=threading.RLock)
    verifier_lock: threading.RLock = field(default_factory=threading.RLock)


CACHE = SnapshotCache()


def _path(name: str) -> str:
    """A snapshot file's path, in the directory the setting names now."""

    return os.fspath(mds_files.snapshot_file(name))


def _clean_metadata_cache_value(value: Any) -> str | None:
    """Return a trimmed string value from cached metadata state if present."""

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def load_metadata_cache_entry() -> dict[str, str | None]:
    """Load cached metadata headers used for conditional download requests."""

    try:
        with open(_path(mds_files.VERIFIED_META), "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(cached, dict):
        return {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = mds_files.format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _load_verified_metadata_payload() -> dict[str, Any] | None:
    try:
        with open(_path(mds_files.VERIFIED), "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def load_verified_entries() -> list[Any] | None:
    """The verified snapshot's entries as its JSON holds them, every field the BLOB
    has (``fido2``'s dataclasses drop those they do not model); None without a
    readable file. Read once for each version of the file, and never parsed into
    ``fido2``'s dataclasses."""

    try:
        verified_mtime = os.path.getmtime(_path(mds_files.VERIFIED))
    except OSError:
        return None
    if CACHE.raw_entries_mtime == verified_mtime:
        return CACHE.raw_entries

    with CACHE.metadata_lock:
        if CACHE.raw_entries_mtime == verified_mtime:
            return CACHE.raw_entries
        payload = _load_verified_metadata_payload()
        entries = payload.get("entries") if payload is not None else None
        CACHE.raw_entries = entries if isinstance(entries, list) else None
        CACHE.raw_entries_mtime = verified_mtime
        return CACHE.raw_entries


def _load_packaged_explorer_meta(snapshot_path: str | None = None) -> dict[str, Any] | None:
    """Return a packaged snapshot's meta when it describes the verified snapshot.

    The snapshot tool writes every packaged file and its meta in one run, so
    matching ``no``, ``etag`` and generation time mean the packaged snapshot is
    current. File mtimes cannot be used for this: checkouts and image builds do
    not preserve their relative order. Defaults to the explorer snapshot.
    """

    path = snapshot_path or _path(mds_files.EXPLORER)
    try:
        with open(path + ".meta.json", "r", encoding="utf-8") as handle:
            explorer_meta = json.load(handle)
        with open(_path(mds_files.VERIFIED_META), "r", encoding="utf-8") as handle:
            verified_meta = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(explorer_meta, dict) or not isinstance(verified_meta, dict):
        return None

    explorer_key = (
        explorer_meta.get("no"),
        explorer_meta.get("etag"),
        explorer_meta.get("generatedAt"),
    )
    verified_key = (
        verified_meta.get("no"),
        verified_meta.get("etag"),
        verified_meta.get("generated_at"),
    )
    if None in explorer_key or explorer_key != verified_key:
        return None
    return explorer_meta


def load_packaged_snapshot_meta() -> dict[str, Any] | None:
    """The meta of the snapshot browsers load (``fido-mds3.explorer.full.json``),
    when the file is there and its meta describes the verified snapshot; else None.

    Only then is the static file what the explorer API would answer for a session
    without uploads, so only then is the page sent to it.
    """

    path = _path(mds_files.EXPLORER_FULL)
    if not os.path.isfile(path):
        return None
    return _load_packaged_explorer_meta(path)


def _mtimes(*names: str) -> tuple[float | None, ...]:
    """The snapshot files' modification times, None for a missing one.

    A cache built from several files is keyed on all of them, read before they
    are: a snapshot replaced file by file under a running instance can then be
    read half old, half new, but never kept that way, since the key it was
    cached under no longer matches once the last file lands."""

    mtimes: list[float | None] = []
    for name in names:
        try:
            mtimes.append(os.path.getmtime(_path(name)))
        except OSError:
            mtimes.append(None)
    return tuple(mtimes)


def _load_base_explorer_snapshot() -> tuple[dict[str, Any] | None, tuple[float | None, ...] | None]:
    cache_marker = _mtimes(
        mds_files.EXPLORER,
        mds_files.VERIFIED,
        mds_files.EXPLORER_META,
        mds_files.VERIFIED_META,
    )
    explorer_mtime, verified_mtime = cache_marker[:2]
    if (
        CACHE.explorer is not None
        and CACHE.explorer_mtime == cache_marker
    ):
        return CACHE.explorer, cache_marker

    with CACHE.explorer_lock:
        if (
            CACHE.explorer is not None
            and CACHE.explorer_mtime == cache_marker
        ):
            return CACHE.explorer, cache_marker

        snapshot: dict[str, Any] | None = None

        packaged_is_current = explorer_mtime is not None and (
            verified_mtime is None
            or explorer_mtime >= verified_mtime
            or _load_packaged_explorer_meta() is not None
        )
        if packaged_is_current:
            try:
                with open(_path(mds_files.EXPLORER), "r", encoding="utf-8") as explorer_file:
                    loaded = json.load(explorer_file)
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict):
                snapshot = loaded

        if snapshot is None:
            payload = _load_verified_metadata_payload()
            if payload is not None:
                snapshot = build_explorer_snapshot(payload, load_metadata_cache_entry())

        CACHE.explorer = snapshot
        CACHE.explorer_mtime = cache_marker
        return snapshot, cache_marker


def _load_base_full_snapshot() -> tuple[dict[str, Any] | None, tuple[float | None, ...]]:
    cache_marker = _mtimes(
        mds_files.EXPLORER_FULL,
        mds_files.VERIFIED,
        mds_files.EXPLORER_FULL_META,
        mds_files.VERIFIED_META,
    )

    if (
        CACHE.full is not None
        and CACHE.full_mtime == cache_marker
    ):
        return CACHE.full, cache_marker

    with CACHE.full_lock:
        if (
            CACHE.full is not None
            and CACHE.full_mtime == cache_marker
        ):
            return CACHE.full, cache_marker

        snapshot: dict[str, Any] | None = None

        # The packaged full snapshot is built by the same code as the fallback
        # below; loading it avoids re-parsing every attestation certificate.
        if _load_packaged_explorer_meta(_path(mds_files.EXPLORER_FULL)) is not None:
            try:
                with open(_path(mds_files.EXPLORER_FULL), "r", encoding="utf-8") as full_file:
                    loaded = json.load(full_file)
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
                snapshot = loaded

        if snapshot is None:
            payload = _load_verified_metadata_payload()
            if payload is not None:
                snapshot = build_bootstrap_snapshot(payload, load_metadata_cache_entry())

        CACHE.full = snapshot
        CACHE.full_mtime = cache_marker
        return snapshot, cache_marker


def load_explorer_files() -> mds_explorer_files.ExplorerFiles | None:
    """The browsers' files of the full snapshot on disk (``explorer_files``),
    derived once for each snapshot, from the very snapshot the cache holds."""

    snapshot, cache_marker = _load_base_full_snapshot()
    if snapshot is None:
        return None
    if CACHE.explorer_files is not None and CACHE.explorer_files_mtime == cache_marker:
        return CACHE.explorer_files
    with CACHE.explorer_files_lock:
        if CACHE.explorer_files is not None and CACHE.explorer_files_mtime == cache_marker:
            return CACHE.explorer_files
        files = mds_explorer_files.build_explorer_files(snapshot)
        CACHE.explorer_files = files
        CACHE.explorer_files_mtime = cache_marker
        return files


def load_packaged_explorer_summary() -> dict[str, Any]:
    # The summary is only the snapshot's meta block, which the packaged meta
    # file already holds; avoid parsing the multi-megabyte snapshot for it.
    if CACHE.explorer is None:
        packaged_meta = _load_packaged_explorer_meta()
        if packaged_meta is not None:
            return dict(packaged_meta)

    snapshot, _ = _load_base_explorer_snapshot()
    if snapshot and isinstance(snapshot.get("meta"), Mapping):
        return dict(snapshot["meta"])

    payload = _load_verified_metadata_payload()
    if payload is None:
        return {}

    return build_explorer_snapshot(payload, load_metadata_cache_entry()).get("meta", {})
