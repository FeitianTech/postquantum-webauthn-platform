"""Each of a visitor's uploads as their listings show it: its row in the explorer
(``mds.effective`` lists the rows) and its item in Manage Metadata, and what a registration's
lookup reads of it (``mds.verifier``). Each is worked out once
from its statement when it is saved, and written into the info file beside it
(``stored_form``); a listing reads it from there, and reads and parses the upload itself
only when its info keeps none it can use (one saved before, or under another format). What
was read is kept, by namespace, stored name and version, for every later listing: one
listing of the namespace (``uploads.list_stored_uploads``) says what was written since, and
only that is read again. Kept in memory, per process, within a budget; the upload's own
entry stays the record, and a registration's lookup reads what it finds from there."""
from __future__ import annotations

import importlib.metadata
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fido2.mds3 import MetadataBlobPayloadEntry, filter_revoked

from . import entries as mds_entries
from . import explorer_files
from . import uploads as mds_uploads
from .build import build_explorer_entry
from .statement_fields import lookup_keys

# What the kept uploads may weigh: their rows and items by their JSON (in memory they take
# about two and a half times that), their lookup keys by their size in memory. A namespace at
# its count quota (2,000 uploads) with every row at ``ROW_BOUND_BYTES`` beside its item and
# a few key identifiers, or some 12,000 uploads of the BLOB's own entries. One heavier than
# an eighth of it would be read each time instead.
BUDGET_BYTES = 20 * 2**20
# What a kept upload weighs beside its JSON, and one that does not read; and what its lookup
# keys weigh in memory, with each key identifier's.
_OVERHEAD_BYTES = 256
_VERIFIER_KEYS_BYTES = 250
_KEY_IDENTIFIER_BYTES = 61
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
# An upload's attestation key identifiers are kept up to this many, eight times the most a real
# entry has (8 in MDS no. 302; 1 in the fixture snapshot): with more, a lookup by a chain reads
# the upload again.
KEY_IDENTIFIERS_BOUND = 64
# The shape of what an upload's info file keeps for its listings (``stored_form``). Bump it when
# that shape, or what a row, an item or a lookup key holds, changes (a test pins one upload's):
# an info file of another format is not read, and its upload is read and worked out instead.
# With it, the explorer's ``DERIVED_FORMAT``, which moves when what it builds of an entry
# does, and fido2's version, whose reading of an entry gives the lookup keys.
ROW_FORMAT = 1
STORED_FORMAT = f"{ROW_FORMAT}.{explorer_files.DERIVED_FORMAT} fido2 {importlib.metadata.version('fido2')}"


@dataclass(frozen=True)
class VerifierKeys:
    """What a registration's lookup reads of an upload (``mds.verifier``), from its entry as
    fido2 read it: the AAGUID its statement names (``hides``: the packaged entries and older
    uploads of it), its own AAGUID, whether a status report revokes it, and its attestation
    key identifiers (None past ``KEY_IDENTIFIERS_BOUND``)."""

    hides: str | None
    aaguid: bytes | None
    revoked: bool
    key_identifiers: tuple[bytes, ...] | None


def verifier_keys(entry: MetadataBlobPayloadEntry) -> VerifierKeys:
    identifiers = tuple(entry.attestation_certificate_key_identifiers or ())
    return VerifierKeys(
        hides=mds_entries._extract_entry_aaguid(entry),
        aaguid=bytes(entry.aaguid) if entry.aaguid else None,
        revoked=not filter_revoked(entry),
        key_identifiers=identifiers if len(identifiers) <= KEY_IDENTIFIERS_BOUND else None,
    )


@dataclass(frozen=True)
class ListedUpload:
    """One upload as its listings show it: its stored name and when it was written; its item
    in Manage Metadata (``uploads.serialize_session_metadata_item``); its row in the explorer
    (``explorer_files.list_row``) at index 0, its icon '' when a file is made of it, whose
    name is ``icon_file``; what a lookup by AAGUID or AAID reads of its statement
    (``statement_fields.lookup_keys``); and what a registration's lookup reads of its entry.
    Every listing shares them: what changes a row changes a copy."""

    filename: str
    mtime: float | None
    item: dict[str, Any]
    row: dict[str, Any]
    icon_file: str | None
    aaguid_key: str
    aaid: str | None
    verifier_keys: VerifierKeys


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
        verifier_keys=verifier_keys(item.entry),
    )


def stored_form(item: mds_uploads.SessionMetadataItem) -> dict[str, Any]:
    """What a listing keeps of the upload ``item``, as its info file holds it when it is saved
    (``uploads.save_session_metadata_item``): JSON that ``_kept_from`` reads back as the
    ``ListedUpload`` worked out from the upload, its bytes as hex."""

    upload = _listed_upload(item)
    keys = upload.verifier_keys
    return {
        "format": STORED_FORMAT,
        "item": upload.item,
        "row": upload.row,
        "icon_file": upload.icon_file,
        "aaguid_key": upload.aaguid_key,
        "aaid": upload.aaid,
        "hides": keys.hides,
        "aaguid": keys.aaguid.hex() if keys.aaguid is not None else None,
        "revoked": keys.revoked,
        "key_identifiers": [key.hex() for key in keys.key_identifiers] if keys.key_identifiers is not None else None,
    }


# What each member of a stored form must be for it to be read (``_kept_from``).
_OPTIONAL_TEXT = (str, type(None))
_STORED_TYPES = {
    "item": dict, "row": dict, "icon_file": _OPTIONAL_TEXT, "aaguid_key": str, "aaid": _OPTIONAL_TEXT,
    "hides": _OPTIONAL_TEXT, "aaguid": _OPTIONAL_TEXT, "revoked": bool, "key_identifiers": (list, type(None)),
}


def _kept_from(upload: mds_uploads.StoredUpload, stored: dict[str, Any] | None) -> ListedUpload | None:
    """The upload as its info file keeps it (``stored_form``); None without one of this format
    that reads as one, and the upload is then read and worked out."""

    if stored is None or stored.get("format") != STORED_FORMAT:
        return None
    if not all(key in stored and isinstance(stored[key], types) for key, types in _STORED_TYPES.items()):
        return None
    aaguid, identifiers = stored["aaguid"], stored["key_identifiers"]
    try:
        keys = VerifierKeys(
            hides=stored["hides"],
            aaguid=bytes.fromhex(aaguid) if aaguid is not None else None,
            revoked=stored["revoked"],
            key_identifiers=tuple(bytes.fromhex(key) for key in identifiers) if identifiers is not None else None,
        )
    except (TypeError, ValueError):
        return None
    return ListedUpload(
        filename=upload.filename, mtime=upload.mtime, item=stored["item"], row=stored["row"],
        icon_file=stored["icon_file"], aaguid_key=stored["aaguid_key"], aaid=stored["aaid"], verifier_keys=keys,
    )


def _weight(upload: ListedUpload | None) -> int:
    if upload is None:
        return _OVERHEAD_BYTES
    identifiers = upload.verifier_keys.key_identifiers or ()
    keys = _VERIFIER_KEYS_BYTES + _KEY_IDENTIFIER_BYTES * len(identifiers)
    return _OVERHEAD_BYTES + len(json.dumps([upload.row, upload.item])) + keys


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
    """The visitor's uploads, the newest first (one that does not read is left out), each
    read once for its version: from its info file, else worked out from the upload."""

    return list_namespace_uploads(session_id)[1]


def list_namespace_uploads(session_id: str | None = None) -> tuple[str, list[ListedUpload]]:
    """The visitor's namespace ('' without one) and its uploads, as ``list_uploads`` lists them."""

    namespace, stored = mds_uploads.list_stored_uploads(session_id)
    listed: list[ListedUpload] = []
    for upload in stored:
        key = (namespace, upload.filename)
        found, kept = KEPT.get(key, upload.version)
        if not found:
            info = mds_uploads.read_stored_info(namespace, upload)
            kept = _kept_from(upload, mds_uploads.stored_listing(upload, info))
            if kept is None:
                item = mds_uploads.read_stored_upload(namespace, upload, info)
                kept = _listed_upload(item) if item is not None else None
            KEPT.put(key, upload.version, kept)
        if kept is not None:
            listed.append(kept)
    listed.sort(key=lambda kept_upload: kept_upload.mtime or 0, reverse=True)
    return namespace, listed
