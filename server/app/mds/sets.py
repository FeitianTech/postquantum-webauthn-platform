"""The FIDO MDS snapshot in Cloud Storage: immutable sets and the pointer to one.

A set is the seven snapshot files under ``<prefix>/sets/<format>/<no>-<token>/``,
each uploaded only if no object has its name yet, payloads first and metas last
(``mds_files.WRITE_ORDER``). ``<prefix>/current.json`` names the current set
with every file's SHA-256 and size; it is written after its set is complete, only
if it is still the object its writer read (its generation), and only forward: a
set whose ``no`` is not above the current one's is not published. So a reader that
follows the pointer finds a complete set, two writers at once leave one pointer
(the other deletes the set it wrote), and a failed or refused publish leaves the
current set where it was. A publish then deletes the set two back (the pointer's
``previous`` before it), never the one it replaced, which an instance may still be
reading.

A leaf like ``mds_files``: it imports nothing from the app but the storage
helpers, so the updater publishes with it without building the Flask app.
docs/MDS_SNAPSHOT.md has the whole picture.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..storage import cloud
from . import files as mds_files

logger = logging.getLogger(__name__)

# The layout of a set and its pointer. A reader ignores a pointer of a format it
# does not know, and a writer does not replace one.
FORMAT = 1

PREFIX_ENV = "FIDO_SERVER_MDS_GCS_PREFIX"
DEFAULT_PREFIX = "mds"
POINTER = "current.json"


class SnapshotSetError(Exception):
    """A set that cannot be used: a file missing, or not the one the pointer names."""


@dataclass(frozen=True)
class Published:
    """What a publish did: ``"published"``, ``"current"`` (the bucket already has
    this snapshot or a later one) or ``"lost"`` (another writer's pointer landed
    first); and the pointer the bucket holds afterwards, as far as this writer knows."""

    outcome: str
    pointer: dict[str, Any] | None


def prefix() -> str:
    return cloud.normalise_blob_prefix(os.environ.get(PREFIX_ENV, DEFAULT_PREFIX))


def pointer_name() -> str:
    return f"{prefix()}{POINTER}"


def _content_type(name: str) -> str | None:
    return "application/json" if name.endswith(".json") else None


def _describe(files: Mapping[str, bytes]) -> dict[str, Any]:
    meta = json.loads(files[mds_files.VERIFIED_META])
    return {
        "no": meta.get("no"),
        "etag": meta.get("etag"),
        "generatedAt": meta.get("generated_at"),
        "nextUpdate": meta.get("nextUpdate"),
        "files": {
            name: {"sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
            for name in mds_files.SNAPSHOT_FILENAMES
        },
    }


def usable(pointer: Any) -> bool:
    """Whether ``pointer`` is one this code can follow."""

    return (
        isinstance(pointer, dict)
        and pointer.get("format") == FORMAT
        and isinstance(pointer.get("set"), str)
        and isinstance(pointer.get("no"), int)
        and isinstance(pointer.get("files"), dict)
        and all(isinstance(pointer["files"].get(name), dict) for name in mds_files.SNAPSHOT_FILENAMES)
    )


def read_pointer(*, timeout: float | None = None, attempts: int | None = None) -> tuple[Any, int]:
    """The pointer as stored (None when there is none, or it is not JSON) and its generation."""

    options: dict[str, Any] = {"timeout": timeout}
    if attempts is not None:
        options["attempts"] = attempts
    data, generation = cloud.download_bytes_with_generation(pointer_name(), **options)
    if data is None:
        return None, generation
    try:
        return json.loads(data), generation
    except ValueError:
        return None, generation


def _delete_set(set_name: str) -> None:
    for name in mds_files.SNAPSHOT_FILENAMES:
        try:
            cloud.delete_blob(set_name + name)
        except Exception as exc:  # the set stays behind, unreferenced
            logger.warning("Could not delete %s%s: %s", set_name, name, exc)


def publish(files: Mapping[str, bytes]) -> Published:
    """Publish a verified snapshot's seven files as a set and point to it.

    The caller has verified the BLOB (``tools/update_mds_snapshot.py``); nothing
    here trusts files it did not get from there or from a set the pointer named.
    Raises when the bucket fails; the pointer is then where it was.
    """

    description = _describe(files)
    current, generation = read_pointer()
    if current is not None and not usable(current):
        raise SnapshotSetError(f"{pointer_name()} is not a pointer this code knows; not replacing it.")
    if current is not None and current["no"] >= description["no"]:
        return Published("current", current)

    set_name = f"{prefix()}sets/{FORMAT}/{description['no']}-{secrets.token_hex(6)}/"
    uploaded: list[str] = []
    try:
        for name in mds_files.WRITE_ORDER:
            if not cloud.upload_bytes_if_generation(
                set_name + name, files[name], generation=0, content_type=_content_type(name)
            ):
                raise SnapshotSetError(f"{set_name}{name} already exists")
            uploaded.append(name)
    except BaseException:
        for name in uploaded:
            try:
                cloud.delete_blob(set_name + name)
            except Exception as exc:
                logger.warning("Could not delete %s%s: %s", set_name, name, exc)
        raise

    pointer = {
        "format": FORMAT,
        "set": set_name,
        **description,
        "previous": current["set"] if current is not None else None,
        "publishedAt": datetime.now(timezone.utc).isoformat(),
    }
    written = cloud.upload_bytes_if_generation(
        pointer_name(),
        json.dumps(pointer, indent=2, sort_keys=True).encode("utf-8"),
        generation=generation,
        content_type="application/json",
    )
    if not written:
        _delete_set(set_name)
        winner, _ = read_pointer()
        return Published("lost", winner if usable(winner) else None)

    two_back = current.get("previous") if current is not None else None
    if isinstance(two_back, str) and two_back.startswith(f"{prefix()}sets/"):
        _delete_set(two_back)
    return Published("published", pointer)


def download_set(pointer: Mapping[str, Any], *, timeout: float | None = None) -> dict[str, bytes]:
    """The seven files of the set ``pointer`` names, each checked against it."""

    files: dict[str, bytes] = {}
    for name in mds_files.SNAPSHOT_FILENAMES:
        expected = pointer["files"][name]
        data, _generation = cloud.download_bytes_with_generation(pointer["set"] + name, timeout=timeout)
        if data is None:
            raise SnapshotSetError(f"{pointer['set']}{name} is missing")
        if len(data) != expected.get("size") or hashlib.sha256(data).hexdigest() != expected.get("sha256"):
            raise SnapshotSetError(f"{pointer['set']}{name} is not the file the pointer names")
        files[name] = data
    return files
