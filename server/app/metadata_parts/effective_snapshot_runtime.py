"""Effective snapshot composition and metadata entry resolution helpers."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..mds_snapshot import build_entry_id, build_explorer_entry, normalise_aaguid_key
from . import base_snapshot_runtime, session_items_runtime

if TYPE_CHECKING:  # annotation-only, so no runtime import edge is needed
    from .session_items_runtime import SessionMetadataItem


def _build_session_snapshot_entry(
    item: SessionMetadataItem,
    *,
    index: int,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> dict[str, Any] | None:
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


def _session_item_source_info(item: SessionMetadataItem) -> dict[str, Any]:
    info: dict[str, Any] = {"storedFilename": item.filename}
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
    entry_id: str | None = None,
    aaguid: str | None = None,
    aaid: str | None = None,
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
    base_snapshot: Mapping[str, Any] | None,
    *,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> dict[str, Any]:
    base_meta: dict[str, Any] = {}
    raw_base_entries: list[Mapping[str, Any]] = []

    if base_snapshot:
        if isinstance(base_snapshot.get("meta"), Mapping):
            base_meta = dict(base_snapshot["meta"])
        raw_entries = base_snapshot.get("entries")
        if isinstance(raw_entries, list):
            raw_base_entries = [entry for entry in raw_entries if isinstance(entry, Mapping)]

    session_items = session_items_runtime.list_session_metadata_items()

    if not session_items:
        # Sessions without uploads (nearly all of them) share the cached base
        # entries; the result is only serialised, so copying 500+ entries per
        # request is unnecessary.
        meta = dict(base_meta)
        meta["entryCount"] = len(raw_base_entries)
        meta["baseEntryCount"] = len(raw_base_entries)
        meta["customEntryCount"] = 0
        meta["hasCustomEntries"] = False
        return {"meta": meta, "entries": raw_base_entries}

    base_entries = [dict(entry) for entry in raw_base_entries]
    custom_entries: list[dict[str, Any]] = []
    seen_aaguids: set[str] = set()

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


def load_effective_explorer_snapshot() -> dict[str, Any]:
    base_snapshot, _ = base_snapshot_runtime._load_base_explorer_snapshot()
    return _compose_effective_snapshot(base_snapshot, include_detail=False)


def load_effective_full_snapshot() -> dict[str, Any]:
    base_snapshot, _ = base_snapshot_runtime._load_base_full_snapshot()
    return _compose_effective_snapshot(
        base_snapshot,
        include_detail=True,
        include_raw_entry=False,
        compact_detail=True,
    )


def resolve_effective_metadata_entry(
    *,
    entry_id: str | None = None,
    aaguid: str | None = None,
    aaid: str | None = None,
) -> dict[str, Any] | None:
    base_summary = base_snapshot_runtime.load_packaged_explorer_summary()
    session_items = session_items_runtime.list_session_metadata_items()
    seen_aaguids: set[str] = set()

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

    base_metadata, _ = base_snapshot_runtime._load_base_metadata()
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
