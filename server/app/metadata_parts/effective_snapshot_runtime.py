"""Effective snapshot composition and metadata entry resolution helpers."""
from __future__ import annotations


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
