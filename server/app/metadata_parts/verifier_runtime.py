"""Metadata merge, trust-anchor, and verifier helpers."""
from __future__ import annotations


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
