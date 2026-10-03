"""The MDS explorer's files as browsers load them, derived from the explorer's
full snapshot the server already holds; no file of the snapshot changes.

- The list (``LIST_FILENAME``): every entry with what the table shows, filters
  and sorts by, marked lightweight (without its detail or where it came from),
  its icon the URL of an icon file and ``detailUrl`` the URL of its detail.
- The icons: one file for each distinct image, named by its digest.
- Each entry's detail: the entry as the full snapshot holds it, its icon a URL.

Pure: a snapshot in, its files out. ``cache.load_explorer_files`` keeps them
for the snapshot on disk; ``routes/assets.py`` serves them.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .. import encoding

# What this module derives changes with the code, not only with the snapshot:
# the version the files are served under names both, so a page never reads an
# earlier deploy's files under the current version.
DERIVED_FORMAT = 2

URL_PREFIX = "/assets/mds"
LIST_FILENAME = "fido-mds3.explorer.list.json"
ICON_DIRECTORY = "icons"
ENTRY_DIRECTORY = "entries"

# What an entry's detail holds, and where it came from: the entry page reads
# them from the detail, and the list leaves them out.
LIST_LEAVES_OUT = frozenset(
    {
        "metadataStatement",
        "rawEntry",
        "statusReports",
        "biometricStatusReports",
        "rogueListURL",
        "rogueListHash",
        "attestationCertificates",
        "attestationKeyIdentifiers",
        "timeOfLastStatusChange",
        "source",
        "sourceInfo",
        "trustAnchorStatus",
        "snapshotNo",
        "snapshotNextUpdate",
        "snapshotFetchedAt",
        "snapshotGeneratedAt",
    }
)

# The image types an icon file is served as, by the type its data URL declares.
ICON_TYPES = {
    "image/png": "png",
    "image/svg+xml": "svg",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
}


@dataclass(frozen=True)
class Icon:
    data: bytes
    mimetype: str


@dataclass(frozen=True)
class ExplorerFiles:
    """The files of one snapshot: the list (as served: JSON and gzipped; and as
    read, for the per-session explorer API), the icons by file name, and each
    entry's detail (JSON) by entry id."""

    version: str
    listed: dict[str, Any]
    list_json: bytes
    list_gzip: bytes
    icons: dict[str, Icon]
    details: dict[str, bytes]


def snapshot_version(meta: Mapping[str, Any] | None) -> str | None:
    """The snapshot's version: its serial number and a digest of its ETag and
    generation time, or None without a snapshot.

    The snapshot changes at runtime (Cloud Storage, an upstream refresh) and its
    files are cached for a year, so each snapshot needs URLs of its own."""

    if meta is None:
        return None
    digest = hashlib.sha256(
        json.dumps([meta.get("etag"), meta.get("generatedAt")]).encode("utf-8")
    ).hexdigest()[:12]
    return quote(f"{meta.get('no')}.{digest}", safe=".")


def list_url() -> str:
    return f"{URL_PREFIX}/{LIST_FILENAME}"


def icon_url(name: str) -> str:
    return f"{URL_PREFIX}/{ICON_DIRECTORY}/{name}"


def detail_url(entry_id: str, version: str) -> str:
    """Where an entry's detail is: its id encoded whole (an AAID's ``#`` too)."""

    return f"{URL_PREFIX}/{ENTRY_DIRECTORY}/{quote(entry_id, safe='')}?v={version}"


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def icon_file(icon: Any) -> tuple[str, Icon] | None:
    """The file an icon's data URL becomes: its name and its image, or None for
    an icon that stays as it is (no data URL, another type, not base64, or
    data that does not read as base64)."""

    if not isinstance(icon, str) or not icon[:5].lower() == "data:":
        return None
    header, comma, body = icon[5:].partition(",")
    mimetype, _semicolon, transfer = header.partition(";")
    mimetype = mimetype.strip().lower()
    extension = ICON_TYPES.get(mimetype)
    if not comma or extension is None or transfer.strip().lower() != "base64":
        return None
    data = encoding.try_decode_base64(body)
    if not data:
        return None
    return f"{hashlib.sha256(data).hexdigest()[:32]}.{extension}", Icon(data, mimetype)


def build_explorer_files(snapshot: Mapping[str, Any]) -> ExplorerFiles | None:
    """The browsers' files of an explorer's full snapshot, or None without one."""

    meta = snapshot.get("meta") if isinstance(snapshot.get("meta"), Mapping) else None
    snapshot_v = snapshot_version(meta)
    if snapshot_v is None:
        return None
    version = f"{snapshot_v}.{DERIVED_FORMAT}"
    icons: dict[str, Icon] = {}
    details: dict[str, bytes] = {}
    rows: list[dict[str, Any]] = []
    for entry in snapshot.get("entries") or []:
        if not isinstance(entry, Mapping):
            continue
        row = {key: value for key, value in entry.items() if key not in LIST_LEAVES_OUT}
        row["isLightweightEntry"] = True
        file = icon_file(entry.get("icon"))
        if file is not None:
            name, image = file
            icons[name] = image
            row["icon"] = icon_url(name)
        entry_id = str(entry.get("entryId") or "")
        if entry_id:
            details[entry_id] = _json({**entry, "icon": row.get("icon")})
            row["detailUrl"] = detail_url(entry_id, version)
        rows.append(row)
    listed = {"meta": dict(meta or {}), "entries": rows}
    list_json = _json(listed)
    return ExplorerFiles(
        version=version,
        listed=listed,
        list_json=list_json,
        list_gzip=gzip.compress(list_json, compresslevel=9, mtime=0),
        icons=icons,
        details=details,
    )
