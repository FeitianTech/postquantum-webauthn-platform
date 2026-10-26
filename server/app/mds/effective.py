"""Effective snapshot composition and metadata entry resolution helpers."""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from . import cache as mds_cache
from . import uploads as mds_uploads
from .build import build_entry_id, build_explorer_entry, unique_entry_id
from .statement_fields import normalise_aaguid_key


def _build_session_snapshot_entry(
    item: mds_uploads.SessionMetadataItem,
    *,
    index: int,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> dict[str, Any]:
    return build_explorer_entry(
        item.payload,
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


def _session_item_source_info(item: mds_uploads.SessionMetadataItem) -> dict[str, Any]:
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
    aaguid: str | None = None,
    aaid: str | None = None,
) -> bool:
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


def _session_rows(
    session_items: list[mds_uploads.SessionMetadataItem],
    *,
    include_detail: bool,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    """The visitor's uploads as explorer rows, in the order listed (the newest first),
    one per AAGUID (the first listed), and the AAGUIDs they hold."""

    rows: list[dict[str, Any]] = []
    aaguids: set[str] = set()
    for index, item in enumerate(session_items):
        row = _build_session_snapshot_entry(
            item,
            index=index,
            include_detail=include_detail,
            include_raw_entry=include_raw_entry,
            compact_detail=compact_detail,
        )
        aaguid_key = normalise_aaguid_key(row.get("aaguid"))
        if aaguid_key:
            if aaguid_key in aaguids:
                continue
            aaguids.add(aaguid_key)
        rows.append(row)
    return rows, aaguids


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

    session_items = mds_uploads.list_session_metadata_items()

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
    custom_entries, seen_aaguids = _session_rows(
        session_items,
        include_detail=include_detail,
        include_raw_entry=include_raw_entry,
        compact_detail=compact_detail,
    )

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


def load_custom_entries() -> dict[str, Any]:
    """What the page lacks of the visitor's explorer: their uploads as rows (each with its
    detail, the newest first, one per AAGUID) and the counts of the list they make with
    the packaged one. The page holds that list (``explorer_files``) and merges the two,
    an upload hiding the packaged entry with its AAGUID. An upload's id is made unique
    among the rows the page shows: one with a packaged entry's AAID or key identifier,
    or an earlier upload's, gets ``~2`` (``build.unique_entry_id``)."""

    files = mds_cache.load_explorer_files()
    packaged = files.listed["entries"] if files is not None else []
    rows, hidden = _session_rows(
        mds_uploads.list_session_metadata_items(),
        include_detail=True,
        include_raw_entry=False,
        compact_detail=True,
    )
    shown = [row for row in packaged if normalise_aaguid_key(row.get("aaguid")) not in hidden]
    taken = {str(row.get("entryId")): 2 for row in shown if row.get("entryId")}
    for row in rows:
        row["entryId"] = unique_entry_id(str(row["entryId"]), taken)
    return {
        "meta": {
            "entryCount": len(rows) + len(shown),
            "baseEntryCount": len(packaged),
            "customEntryCount": len(rows),
            "hasCustomEntries": bool(rows),
        },
        "entries": rows,
    }


def load_effective_full_snapshot() -> dict[str, Any]:
    """Every entry this session sees: the packaged list's rows (each without its
    detail, which its ``detailUrl`` names) and the session's uploads in full."""

    files = mds_cache.load_explorer_files()
    base_snapshot = files.listed if files is not None else mds_cache._load_base_full_snapshot()[0]
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
    if entry_id:
        return _resolve_by_id(entry_id)

    base_summary = mds_cache.load_packaged_explorer_summary()
    session_items = mds_uploads.list_session_metadata_items()
    seen_aaguids: set[str] = set()

    for index, item in enumerate(session_items):
        payload = item.payload
        if _entry_matches_lookup(payload, aaguid=aaguid, aaid=aaid):
            # As the visitor's explorer list holds it.
            return _build_session_snapshot_entry(
                item, index=index, include_detail=True, include_raw_entry=False, compact_detail=True
            )

        metadata_statement = payload.get("metadataStatement")
        metadata_mapping = metadata_statement if isinstance(metadata_statement, Mapping) else {}
        aaguid_key = normalise_aaguid_key(payload.get("aaguid") or metadata_mapping.get("aaguid"))
        if aaguid_key:
            seen_aaguids.add(aaguid_key)

    # The entry as the BLOB has it, from the verified payload's JSON.
    raw_entries = mds_cache.load_verified_entries()
    if raw_entries is None:
        return None

    for index, payload in enumerate(raw_entries):
        if not isinstance(payload, Mapping):
            continue
        metadata_statement = payload.get("metadataStatement")
        metadata_mapping = metadata_statement if isinstance(metadata_statement, Mapping) else {}
        aaguid_key = normalise_aaguid_key(payload.get("aaguid") or metadata_mapping.get("aaguid"))
        if aaguid_key and aaguid_key in seen_aaguids:
            continue
        if _entry_matches_lookup(payload, aaguid=aaguid, aaid=aaid):
            return _packaged_detail(payload, index, base_summary)

    return None


def _resolve_by_id(entry_id: str) -> dict[str, Any] | None:
    """The entry the visitor's explorer lists as ``entry_id``: an upload by the id its row
    has (``load_custom_entries``), else a packaged entry no upload hides."""

    rows = load_custom_entries()["entries"]
    for row in rows:
        if row["entryId"] == entry_id:
            return row
    hidden = {normalise_aaguid_key(row.get("aaguid")) for row in rows} - {""}
    return _packaged_detail_by_id(entry_id, hidden)


def _packaged_detail_by_id(entry_id: str, hidden_aaguids: set[str]) -> dict[str, Any] | None:
    """The packaged entry with ``entry_id`` as its detail file has it (``mds.explorer_files``,
    whose ids are unique: ``…~2`` names an earlier entry of the same id), unless an upload
    with its AAGUID hides it."""

    files = mds_cache.load_explorer_files()
    detail = files.details.get(entry_id) if files is not None else None
    if detail is None:
        return None
    entry = json.loads(detail)
    aaguid_key = normalise_aaguid_key(entry.get("aaguid"))
    return None if aaguid_key and aaguid_key in hidden_aaguids else entry


def _packaged_detail(payload: Mapping[str, Any], index: int, base_summary: Mapping[str, Any]) -> dict[str, Any]:
    """A packaged entry as its detail file has it (``mds.explorer_files``), or, without
    one, built as the full snapshot builds it."""

    files = mds_cache.load_explorer_files()
    detail = files.details.get(build_entry_id(payload)) if files is not None else None
    if detail is not None:
        return json.loads(detail)
    return build_explorer_entry(
        payload,
        index=index,
        source="packaged",
        trust_anchor_status=True,
        snapshot_meta=base_summary,
        include_detail=True,
        include_raw_entry=False,
        compact_detail=True,
    )
