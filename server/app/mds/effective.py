"""A visitor's uploads as the explorer lists them (``explorer/custom``): rows of the packaged
list's shape, whose icons are served at URLs of their own; and the lookup of an entry with
them in front of the packaged ones."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from . import cache as mds_cache
from . import explorer_files, listed_uploads
from . import uploads as mds_uploads
from .build import build_entry_id, build_explorer_entry, unique_entry_id
from .statement_fields import lookup_keys, normalise_aaguid_key, statement_icon


def icon_url(stored_filename: str) -> str:
    """Where the icon of the visitor's upload ``stored_filename`` is served (``routes/mds.py``)."""

    return f"/api/mds/metadata/custom/{quote(stored_filename, safe='')}/icon"


def _keys_match(keys: tuple[str, str | None], *, aaguid: str | None = None, aaid: str | None = None) -> bool:
    """Whether an entry with ``keys`` (``statement_fields.lookup_keys``) has ``aaguid``, or
    else ``aaid``."""

    entry_aaguid, entry_aaid = keys
    if aaguid:
        lookup_key = normalise_aaguid_key(aaguid)
        return bool(lookup_key) and entry_aaguid == lookup_key
    if aaid:
        return entry_aaid == aaid
    return False


_ListedUpload = tuple[listed_uploads.ListedUpload, dict[str, Any]]


def _session_rows(uploads: list[listed_uploads.ListedUpload]) -> tuple[list[_ListedUpload], set[str]]:
    """The visitor's uploads as rows of the list, each with its upload, in the order listed
    (the newest first), one per AAGUID (the first listed), and the AAGUIDs they hold."""

    rows: list[_ListedUpload] = []
    aaguids: set[str] = set()
    for index, upload in enumerate(uploads):
        row = {**upload.row, "index": index}
        aaguid_key = normalise_aaguid_key(row.get("aaguid"))
        if aaguid_key:
            if aaguid_key in aaguids:
                continue
            aaguids.add(aaguid_key)
        rows.append((upload, row))
    return rows, aaguids


def _name_icons_by_url(uploads: list[_ListedUpload]) -> None:
    """Give each row its icon's URL (``icon_url``) in place of its image, as the packaged
    list does: of uploads with one image, the oldest's, so the page loads it once and a
    newer upload leaves the URLs it holds as they are. An icon no file is made of
    (``explorer_files.icon_file``) stays as it is, as in the packaged list."""

    urls: dict[str, str] = {}
    for upload, row in reversed(uploads):
        if upload.icon_file is not None:
            row["icon"] = urls.setdefault(upload.icon_file, icon_url(upload.filename))


@dataclass(frozen=True)
class _Listed:
    """The visitor's explorer: their uploads as rows, each with its upload, and the AAGUIDs
    the rows hide; how many rows the packaged list has, and how many of them are shown."""

    uploads: list[_ListedUpload]
    hidden: set[str]
    packaged: int
    shown: int


def _listed() -> _Listed:
    """The visitor's uploads as their explorer lists them, beside the packaged list. An
    upload's id is made unique among the rows the page shows: one with a packaged entry's
    AAID or key identifier, or an earlier upload's, gets ``~2`` (``build.unique_entry_id``)."""

    files = mds_cache.load_explorer_files()
    packaged = files.listed["entries"] if files is not None else []
    uploads, hidden = _session_rows(listed_uploads.list_uploads())
    shown = [row for row in packaged if normalise_aaguid_key(row.get("aaguid")) not in hidden]
    taken = {str(row.get("entryId")): 2 for row in shown if row.get("entryId")}
    for _item, row in uploads:
        row["entryId"] = unique_entry_id(str(row["entryId"]), taken)
    _name_icons_by_url(uploads)
    return _Listed(uploads, hidden, len(packaged), len(shown))


def load_custom_entries() -> dict[str, Any]:
    """What the page lacks of the visitor's explorer: their uploads as rows of the packaged
    list's shape (the newest first, one per AAGUID; the entry page resolves each one's
    detail), and the counts of the list they make with the packaged one. The page holds
    that list (``explorer_files``) and merges the two, an upload hiding the packaged entry
    with its AAGUID."""

    listed = _listed()
    rows = [row for _item, row in listed.uploads]
    return {
        "meta": {
            "entryCount": len(rows) + listed.shown,
            "baseEntryCount": listed.packaged,
            "customEntryCount": len(rows),
            "hasCustomEntries": bool(rows),
        },
        "entries": rows,
    }


def resolve_effective_metadata_entry(
    *,
    entry_id: str | None = None,
    aaguid: str | None = None,
    aaid: str | None = None,
) -> dict[str, Any] | None:
    """The entry the visitor's explorer lists as ``entry_id``, else the first it lists with
    ``aaguid`` or ``aaid``: an upload, with its detail, else a packaged entry no upload hides."""

    listed = _listed()
    for upload, row in listed.uploads:
        keys = (upload.aaguid_key, upload.aaid)
        found = (row["entryId"] == entry_id) if entry_id else _keys_match(keys, aaguid=aaguid, aaid=aaid)
        if found:
            return _upload_detail(upload, row)
    if entry_id:
        return _packaged_detail_by_id(entry_id, listed.hidden)
    return _packaged_by_lookup(listed.hidden, aaguid=aaguid, aaid=aaid)


def _upload_detail(upload: listed_uploads.ListedUpload, row: Mapping[str, Any]) -> dict[str, Any] | None:
    """An upload's entry with its detail, read again from its statement, under its row's id
    and with its row's icon: the row is its detail in the list's shape, as a packaged
    entry's is. None once the upload is gone."""

    item = mds_uploads.load_session_metadata_item(upload.filename)
    if item is None:
        return None
    detail = listed_uploads.upload_entry(item, index=row["index"], include_detail=True)
    return {**detail, "entryId": row["entryId"], "icon": row["icon"]}


def upload_icon(stored_filename: str) -> explorer_files.Icon | None:
    """The image of the icon of the visitor's upload ``stored_filename``; None without
    such an upload, and for an icon no file is made of (``explorer_files.icon_file``)."""

    item = mds_uploads.load_session_metadata_item(stored_filename)
    if item is None:
        return None
    file = explorer_files.icon_file(statement_icon(item.payload["metadataStatement"]))
    return file[1] if file is not None else None


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


def _packaged_by_lookup(hidden_aaguids: set[str], *, aaguid: str | None, aaid: str | None) -> dict[str, Any] | None:
    """The first packaged entry with ``aaguid`` or ``aaid`` whose AAGUID no upload has, found
    in the verified payload's JSON (the entries as the BLOB has them)."""

    raw_entries = mds_cache.load_verified_entries()
    if raw_entries is None:
        return None

    base_summary = mds_cache.load_packaged_explorer_summary()
    for index, payload in enumerate(raw_entries):
        if not isinstance(payload, Mapping):
            continue
        keys = lookup_keys(payload)
        if keys[0] and keys[0] in hidden_aaguids:
            continue
        if _keys_match(keys, aaguid=aaguid, aaid=aaid):
            return _packaged_detail(payload, index, base_summary)

    return None


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
