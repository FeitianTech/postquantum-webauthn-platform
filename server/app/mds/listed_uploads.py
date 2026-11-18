"""Each of a visitor's uploads as their listings show it: its row in the explorer
(``mds.effective`` lists the rows) and its item in Manage Metadata. Each is worked out once
from its statement and kept, by namespace, stored name and version, for every later
listing: one listing of the namespace (``uploads.list_stored_uploads``) says what was
written since, and only that is read and parsed again. Kept in memory, per process,
within a budget; the store stays the record."""
from __future__ import annotations

import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import explorer_files
from . import uploads as mds_uploads
from .build import build_explorer_entry
from .statement_fields import lookup_keys

# What the kept uploads may weigh, by the JSON of their rows and items (in memory they take
# about two and a half times that): a namespace at its count quota (2,000 uploads) with every
# row at ``ROW_BOUND_BYTES``, beside its item, or some 12,000 uploads of the BLOB's own
# entries. One heavier than an eighth of it would be worked out each time instead.
BUDGET_BYTES = 20 * 2**20
# What a kept upload weighs beside its JSON, and one that does not read.
_OVERHEAD_BYTES = 256
# A row or item heavier than this as JSON (about twice the heaviest real metadata gives) is
# cut down until it fits (``_bounded``); one at or under it is listed exactly as it is. Texts
# are cut by their weight as JSON (``\uXXXX`` for each character outside ASCII), as the
# answer and the cache weigh them.
ROW_BOUND_BYTES = 8 * 2**10
_TEXT_BOUND = 256
_LIST_BOUND = 16
_LIST_ITEM_BOUND = 32
# What a row cut down to the last keeps: what identifies the entry, and what it came from.
_IDENTIFYING = frozenset({"entryId", "name", "id", "aaguid", "source", "storedFilename"})


@dataclass(frozen=True)
class ListedUpload:
    """One upload as its listings show it: its stored name and when it was written; its item
    in Manage Metadata (``uploads.serialize_session_metadata_item``); its row in the explorer
    (``explorer_files.list_row``) at index 0, its icon '' when a file is made of it, whose
    name is ``icon_file``; and what a lookup by AAGUID or AAID reads of its statement
    (``statement_fields.lookup_keys``). Every listing shares them: what changes a row
    changes a copy."""

    filename: str
    mtime: float | None
    item: dict[str, Any]
    row: dict[str, Any]
    icon_file: str | None
    aaguid_key: str
    aaid: str | None


def upload_entry(item: mds_uploads.SessionMetadataItem, *, index: int, include_detail: bool) -> dict[str, Any]:
    """An upload as the explorer shows it: its row's fields, and with ``include_detail`` its
    detail too, with where it came from."""

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
        include_raw_entry=False,
        compact_detail=True,
        source_info=_source_info(item),
    )


def _source_info(item: mds_uploads.SessionMetadataItem) -> dict[str, Any]:
    info: dict[str, Any] = {"storedFilename": item.filename}
    if item.original_filename:
        info["originalFilename"] = item.original_filename
    if item.uploaded_at:
        info["uploadedAt"] = item.uploaded_at
    if item.mtime is not None:
        info["modifiedAt"] = datetime.fromtimestamp(item.mtime, timezone.utc).isoformat()
    return info


def _cut_text(text: str, bound: int) -> str:
    """``text``, or as much of its start as weighs ``bound`` bytes as JSON with ``...``."""

    weight, end = 0, None
    for index, character in enumerate(text):
        weight += len(json.dumps(character)) - 2
        if end is None and weight > bound - 3:
            end = index
        if weight > bound:
            return text[:end] + "..."
    return text


def _cut_texts(value: Any, bound: int, *, in_lists: bool = False, in_list: bool = False) -> Any:
    """``value`` with each text (with ``in_lists``, each in a list) cut to ``bound`` bytes."""

    if isinstance(value, str):
        return _cut_text(value, bound) if in_list or not in_lists else value
    if isinstance(value, list):
        return [_cut_texts(part, bound, in_lists=in_lists, in_list=True) for part in value]
    if isinstance(value, dict):
        return {key: _cut_texts(part, bound, in_lists=in_lists) for key, part in value.items()}
    return value


def _cut_lists(value: Any, length: int) -> Any:
    if isinstance(value, list):
        return [_cut_lists(part, length) for part in value[:length]]
    if isinstance(value, dict):
        return {key: _cut_lists(part, length) for key, part in value.items()}
    return value


def _identifying(value: Any) -> Any:
    """``value`` with each text and list emptied but under ``_IDENTIFYING``'s keys: every
    field stays, so the page reads the row as any other."""

    if isinstance(value, dict):
        return {key: part if key in _IDENTIFYING else _identifying(part) for key, part in value.items()}
    if isinstance(value, str):
        return ""
    if isinstance(value, list):
        return []
    return value


_CUTS = (
    lambda row: {**row, "icon": ""} if row.get("icon") else row,
    lambda row: _cut_texts(row, _TEXT_BOUND),
    lambda row: _cut_lists(row, _LIST_BOUND),
    lambda row: _cut_texts(row, _LIST_ITEM_BOUND, in_lists=True),
    lambda row: _cut_lists(row, 0),
    _identifying,
)


def _bounded(listed: dict[str, Any]) -> dict[str, Any]:
    """A row or item at most ``ROW_BOUND_BYTES`` as JSON, so that a namespace's every row is
    small enough to keep: one heavier is cut down, step by step until it fits, dropping an
    icon no file is made of (the row then has none, as a statement without one), cutting each
    text with ``...``, keeping the first items of each list, cutting their texts shorter,
    emptying the lists, and last emptying all but what identifies it, whose texts are cut
    already. Statements a client made large are the ones cut."""

    for cut in _CUTS:
        if len(json.dumps(listed)) <= ROW_BOUND_BYTES:
            break
        listed = cut(listed)
    return listed


def _listed_upload(item: mds_uploads.SessionMetadataItem) -> ListedUpload:
    row = explorer_files.list_row(upload_entry(item, index=0, include_detail=False))
    file = explorer_files.icon_file(row["icon"])
    if file is not None:
        row["icon"] = ""
    aaguid_key, aaid = lookup_keys(item.payload)
    return ListedUpload(
        filename=item.filename,
        mtime=item.mtime,
        item=_bounded(mds_uploads.serialize_session_metadata_item(item)),
        row=_bounded(row),
        icon_file=file[0] if file is not None else None,
        aaguid_key=aaguid_key,
        aaid=aaid,
    )


def _weight(upload: ListedUpload | None) -> int:
    if upload is None:
        return _OVERHEAD_BYTES
    return _OVERHEAD_BYTES + len(json.dumps([upload.row, upload.item]))


_Key = tuple[str, str]


class KeptUploads:
    """The uploads worked out, by namespace and stored name, each with the version it was
    worked out from (None for one that did not read); past ``budget``, the least recently
    listed go first."""

    def __init__(self, budget: int = BUDGET_BYTES) -> None:
        self.budget = budget
        self._kept: OrderedDict[_Key, tuple[tuple[Any, ...], ListedUpload | None, int]] = OrderedDict()
        self._total = 0
        self._lock = threading.Lock()

    def get(self, key: _Key, version: tuple[Any, ...]) -> tuple[bool, ListedUpload | None]:
        """Whether ``key`` is kept at ``version``, and what was worked out of it."""

        with self._lock:
            kept = self._kept.get(key)
            if kept is None or kept[0] != version:
                return False, None
            self._kept.move_to_end(key)
            return True, kept[1]

    def put(self, key: _Key, version: tuple[Any, ...], upload: ListedUpload | None) -> None:
        weight = _weight(upload)
        if weight > self.budget // 8:
            return
        with self._lock:
            replaced = self._kept.pop(key, None)
            if replaced is not None:
                self._total -= replaced[2]
            self._kept[key] = (version, upload, weight)
            self._total += weight
            while self._total > self.budget:
                _dropped, (_version, _upload, dropped_weight) = self._kept.popitem(last=False)
                self._total -= dropped_weight


KEPT = KeptUploads()


def list_uploads(session_id: str | None = None) -> list[ListedUpload]:
    """The visitor's uploads, the newest first, as ``uploads.list_session_metadata_items``
    lists them (one that does not read is left out), each read and worked out once for its
    version."""

    namespace, stored = mds_uploads.list_stored_uploads(session_id)
    listed: list[ListedUpload] = []
    for upload in stored:
        key = (namespace, upload.filename)
        found, kept = KEPT.get(key, upload.version)
        if not found:
            item = mds_uploads.read_stored_upload(namespace, upload)
            kept = _listed_upload(item) if item is not None else None
            KEPT.put(key, upload.version, kept)
        if kept is not None:
            listed.append(kept)
    listed.sort(key=lambda kept_upload: kept_upload.mtime or 0, reverse=True)
    return listed
