"""A snapshot's seven files, built from its BLOB, the verified payload and its cache state.

``tools/update_mds_snapshot.py`` writes what this builds; an instance builds the
same from a BLOB it verified (``derive``, from ``mds/provisioning.py``), and the
tests build their fixture with it (``tests/app/metadata/mds_fixture.py``). Pure
and Flask-free, like the rest the updater imports.
"""
from __future__ import annotations

import json
from datetime import datetime

from . import blob as mds_blob
from . import files as mds_files
from . import trust as mds_trust
from .build import build_bootstrap_snapshot, build_explorer_snapshot


def _serialise_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _serialise_compact_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n"


def _finalise_base_full_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    """Add the entry-count fields the explorer API reports for a session without uploads."""

    entries = snapshot.get("entries")
    entry_count = len(entries) if isinstance(entries, list) else 0
    meta = dict(snapshot.get("meta") or {})
    meta["entryCount"] = entry_count
    meta["baseEntryCount"] = entry_count
    meta["customEntryCount"] = 0
    meta["hasCustomEntries"] = False
    return {**snapshot, "meta": meta}


def snapshot_files(
    blob: bytes,
    verified_snapshot: dict[str, object],
    cache_state: dict[str, object],
) -> dict[str, bytes]:
    """The seven files of a snapshot, by name, as the server reads them: the BLOB,
    the verified payload and its cache state, and the explorer views built from
    them."""

    explorer_snapshot = build_explorer_snapshot(verified_snapshot, cache_state)
    # The full snapshot is what the explorer API returns for a session without
    # uploaded metadata; browsers load it as a cacheable static file.
    full_snapshot = _finalise_base_full_snapshot(
        build_bootstrap_snapshot(verified_snapshot, cache_state)
    )
    return {
        mds_files.BLOB: blob,
        mds_files.VERIFIED: _serialise_json(verified_snapshot).encode("utf-8"),
        mds_files.VERIFIED_META: _serialise_json(cache_state).encode("utf-8"),
        mds_files.EXPLORER: _serialise_json(explorer_snapshot).encode("utf-8"),
        mds_files.EXPLORER_META: _serialise_json(explorer_snapshot.get("meta", {})).encode("utf-8"),
        mds_files.EXPLORER_FULL: _serialise_compact_json(full_snapshot).encode("utf-8"),
        mds_files.EXPLORER_FULL_META: _serialise_json(full_snapshot.get("meta", {})).encode("utf-8"),
    }


def derive(blob: bytes, meta: bytes) -> dict[str, bytes]:
    """The seven files of a snapshot from its BLOB and its cache state (the verified
    payload's ``.meta.json``), once the BLOB verifies.

    The BLOB's chain must lead to the pinned root at the time the meta says it was
    fetched (when the updater checked it; a certificate may have expired since), its
    signature must verify, and its signed ``no`` must be the meta's. Raises
    otherwise. The meta is kept as it came.
    """

    cache_state = json.loads(meta)
    if not isinstance(cache_state, dict) or not isinstance(cache_state.get("fetched_at"), str):
        raise ValueError("The snapshot's meta names no time it was fetched")
    fetched_at = datetime.fromisoformat(cache_state["fetched_at"])
    payload = mds_blob.verify_blob(blob, mds_trust.FIDO_METADATA_TRUST_ROOT_CERT, now=fetched_at)
    if payload.get("no") != cache_state.get("no"):
        raise ValueError(f"The BLOB is snapshot no. {payload.get('no')}, its meta no. {cache_state.get('no')}")
    files = snapshot_files(blob, payload, cache_state)
    files[mds_files.VERIFIED_META] = bytes(meta)
    return files
