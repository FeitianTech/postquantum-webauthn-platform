"""Metadata merge, trust-anchor, and verifier helpers."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from flask import g, has_request_context

from fido2.mds3 import (
    MdsAttestationVerifier,
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
)

from . import blob, entry_payload_runtime, sessions
from . import runtime_state as _state

if TYPE_CHECKING:  # annotation-only, so no runtime import edge is needed
    from .sessions import SessionMetadataItem


def _merge_metadata(
    base_metadata: MetadataBlobPayload | None,
    session_items: list[SessionMetadataItem],
) -> MetadataBlobPayload:
    custom_entries: list[MetadataBlobPayloadEntry] = []
    seen_aaguids: set[str] = set()

    for item in session_items:
        entry = item.entry
        aaguid = entry_payload_runtime._extract_entry_aaguid(entry)
        if aaguid and aaguid in seen_aaguids:
            continue
        if aaguid:
            seen_aaguids.add(aaguid)
        custom_entries.append(entry)

    base_entries: list[MetadataBlobPayloadEntry] = []
    if base_metadata is not None:
        for entry in base_metadata.entries:
            aaguid = entry_payload_runtime._extract_entry_aaguid(entry)
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


def metadata_entry_trust_anchor_status(entry: Any) -> bool | None:
    """Return whether *entry* originates from a trust-anchored metadata source.

    Returns ``False`` for session-uploaded entries, the base trust flag for
    entries from the packaged FIDO MDS snapshot, and ``None`` when the origin
    cannot be established. Unknown entries are never reported as trusted.
    """

    if entry is None or not isinstance(entry, MetadataBlobPayloadEntry):
        return None

    entry_id = id(entry)

    # Session-uploaded entries are tracked per request (see get_mds_verifier) so
    # that concurrent requests from other sessions cannot change the outcome.
    request_session_ids = (
        getattr(g, "_mds_session_entry_ids", None) if has_request_context() else None
    )
    if request_session_ids and entry_id in request_session_ids:
        return False
    if entry_id in _state._session_metadata_entry_ids:
        return False
    if entry_id in _state._base_metadata_entry_ids:
        return _state._base_metadata_trust_verified

    return None


def get_mds_verifier() -> MdsAttestationVerifier | None:
    """Return an MDS attestation verifier using session metadata when available."""

    base_metadata, base_mtime = blob._load_base_metadata()
    session_items = sessions.list_session_metadata_items()

    if has_request_context():
        # Holding the entry objects on ``g`` keeps their ids valid for the
        # lifetime of the request.
        session_entries = tuple(
            entry
            for entry in (getattr(item, "entry", None) for item in session_items)
            if entry is not None
        )
        g._mds_session_entries = session_entries
        g._mds_session_entry_ids = frozenset(id(entry) for entry in session_entries)

    if not session_items:
        if base_metadata is None:
            _state._base_verifier_cache = None
            _state._base_verifier_mtime = base_mtime
            return None

        if (
            _state._base_verifier_cache is not None
            and _state._base_verifier_mtime is not None
            and _state._base_verifier_mtime == base_mtime
        ):
            return _state._base_verifier_cache

        with _state._base_verifier_lock:
            if (
                _state._base_verifier_cache is not None
                and _state._base_verifier_mtime is not None
                and _state._base_verifier_mtime == base_mtime
            ):
                return _state._base_verifier_cache

            verifier = MdsAttestationVerifier(base_metadata)
            _state._base_verifier_cache = verifier
            _state._base_verifier_mtime = base_mtime
            return verifier

    if base_metadata is None and not session_items:
        return None

    metadata = _merge_metadata(base_metadata, session_items)
    return MdsAttestationVerifier(metadata)
