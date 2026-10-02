"""Runtime provisioning of the packaged FIDO MDS snapshot.

The snapshot is a ~30 MB set of generated files (the signed BLOB, the verified
payload and the explorer views). It is not tracked in git and is not baked into
the container image, so a daily refresh no longer rewrites repository history or
invalidates a Docker layer. Instead the files are materialised into
the snapshot directory (``instance/mds-snapshot`` unless
``FIDO_SERVER_MDS_SNAPSHOT_DIR`` names another, ``server.app.mds.files``) on
demand, in three tiers:

1. **Local files.** Anything already on disk is used as-is. This is the path a
   developer gets after running ``python tools/update_mds_snapshot.py`` once,
   and it is the only tier that needs no network access at all.
2. **Cloud Storage.** When GCS is configured (``FIDO_SERVER_GCS_ENABLED``), the
   set ``<bucket>/mds/current.json`` points to is downloaded, each file checked
   against the pointer (``mds.sets``); without a usable one, the files
   missing locally from the flat ``<bucket>/mds/<file>`` objects of earlier
   releases. This is how a Cloud Run cold start gets the snapshot without
   shipping it in the image.
3. **Upstream refresh.** As a last resort the packaged updater is run, which
   downloads the BLOB from the FIDO Alliance and verifies it against the pinned
   trust root before writing anything. The result is published to Cloud Storage
   as a set so the next cold start stops at tier 2.

Tier 3 is opt-in through ``FIDO_SERVER_MDS_FETCH_UPSTREAM`` and defaults to the
GCS setting: on by default in a deployed service, off by default locally so a
first request never blocks on a 10 MB download. With every tier unavailable the
application still starts and serves; the metadata APIs report that no snapshot
is available, exactly as they already did for a missing snapshot.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import threading
import time
from pathlib import Path

from ..env_flags import parse_env_flag
from ..storage import cloud
from . import files as mds_files
from . import sets as snapshot_sets

logger = logging.getLogger(__name__)

__all__ = [
    "SNAPSHOT_FILENAMES",
    "ensure_snapshot_available",
    "follow_newer_snapshot",
    "missing_snapshot_files",
    "snapshot_blob_name",
    "upstream_refresh_enabled",
    "write_snapshot_file",
]

# Every file tools/update_mds_snapshot.py writes, in one set. The payloads and
# their .meta.json companions are generated together and describe each other, so
# they are provisioned together too; mixing generations would make the freshness
# check in mds/cache.py compare mismatched snapshots.
SNAPSHOT_FILENAMES = mds_files.SNAPSHOT_FILENAMES


_UPSTREAM_ENV_FLAG = "FIDO_SERVER_MDS_FETCH_UPSTREAM"

_provision_lock = threading.Lock()
_provision_state: dict[str, object] = {"attempted": False, "source": None}

# How often a running instance asks the bucket whether it points to a newer set.
_POINTER_CHECK_ENV = "FIDO_SERVER_MDS_POINTER_CHECK_SECONDS"
_DEFAULT_POINTER_CHECK_SECONDS = 900.0
# The pointer is read inside a visitor's request: briefly, once.
_POINTER_TIMEOUT_SECONDS = 5.0
_SET_TIMEOUT_SECONDS = 60.0
_follow_lock = threading.Lock()
_follow_state: dict[str, float | None] = {"checked_at": None}


def snapshot_path(filename: str) -> Path:
    return mds_files.snapshot_file(filename)


def snapshot_blob_name(filename: str) -> str:
    # The flat objects of the snapshot's first layout, under the sets' own prefix.
    return cloud.build_blob_name(filename, prefix=snapshot_sets.prefix())


def missing_snapshot_files() -> tuple[str, ...]:
    """Return the snapshot files that are not present on local disk."""

    return tuple(name for name in SNAPSHOT_FILENAMES if not snapshot_path(name).is_file())


def upstream_refresh_enabled() -> bool:
    """Return whether tier 3 (refresh from the FIDO Alliance) may run."""

    explicit = parse_env_flag(_UPSTREAM_ENV_FLAG)
    if explicit is not None:
        return explicit
    # A deployed service can repopulate its own bucket; a developer should not
    # silently pull 10 MB because a file happens to be missing.
    return cloud.gcs_enabled()


def write_snapshot_file(filename: str, data: bytes) -> Path:
    """Write one snapshot file whole."""

    path = snapshot_path(filename)
    mds_files.write_file(path, data)
    return path


def _write_set(files: dict[str, bytes]) -> None:
    """Write a complete set, payloads first and metas last (``WRITE_ORDER``)."""

    for filename in mds_files.WRITE_ORDER:
        write_snapshot_file(filename, files[filename])


def _download_set_from_gcs() -> dict | None:
    """Fetch the set the bucket's pointer names; return the pointer, or None
    when there is no usable pointer or its set cannot be read whole."""

    if not cloud.gcs_enabled():
        return None
    try:
        pointer, _generation = snapshot_sets.read_pointer()
        if not snapshot_sets.usable(pointer):
            return None
        files = snapshot_sets.download_set(pointer)
    except Exception as exc:
        logger.warning("Could not download the MDS snapshot set from Cloud Storage: %s", exc)
        return None
    _write_set(files)
    return pointer


def _download_from_gcs(missing: tuple[str, ...]) -> tuple[str, ...]:
    """Fetch ``missing`` from the flat objects of earlier releases; return the names still missing."""

    if not cloud.gcs_enabled():
        return missing

    remaining: list[str] = []
    for filename in missing:
        try:
            data = cloud.download_bytes(snapshot_blob_name(filename))
        except Exception as exc:  # pragma: no cover - network/credential failure
            logger.warning(
                "Could not download MDS snapshot file %s from Cloud Storage: %s",
                filename,
                exc,
            )
            remaining.append(filename)
            continue

        if data is None:
            remaining.append(filename)
            continue
        write_snapshot_file(filename, data)

    return tuple(remaining)


def _refresh_from_upstream() -> bool:
    """Run the packaged updater, which verifies the BLOB before writing it."""

    try:
        from tools import update_mds_snapshot
    except ImportError:
        logger.warning(
            "The MDS snapshot updater is not packaged with this build; "
            "cannot refresh the snapshot from the FIDO Alliance."
        )
        return False

    try:
        # Its own arguments, not the server's (gunicorn's argv).
        return update_mds_snapshot.main([]) == 0
    except Exception as exc:  # pragma: no cover - network/parse failure
        logger.warning("Refreshing the MDS snapshot from upstream failed: %s", exc)
        return False


def _publish_to_gcs() -> None:
    """Publish the snapshot the updater just verified and wrote as the bucket's set."""

    if not cloud.gcs_enabled():
        return
    try:
        files = {name: snapshot_path(name).read_bytes() for name in SNAPSHOT_FILENAMES}
        result = snapshot_sets.publish(files)
    except Exception as exc:
        logger.warning("Could not publish the MDS snapshot to Cloud Storage: %s", exc)
        return
    logger.info("Publishing the MDS snapshot to Cloud Storage: %s.", result.outcome)


def ensure_snapshot_available(*, force: bool = False) -> str:
    """Materialise the MDS snapshot into the snapshot directory.

    Returns the tier that satisfied the request: ``"local"``, ``"gcs"``,
    ``"upstream"`` or ``"unavailable"``. Runs at most once per process unless
    ``force`` is set, so the threads of a cold instance share one download.
    """

    with _provision_lock:
        if _provision_state["attempted"] and not force:
            return str(_provision_state["source"])

        missing = missing_snapshot_files()
        if not missing:
            source = "local"
        else:
            logger.info(
                "MDS snapshot files missing locally (%s); provisioning.",
                ", ".join(missing),
            )
            if _download_set_from_gcs() is not None or not _download_from_gcs(missing):
                source = "gcs"
            elif upstream_refresh_enabled() and _refresh_from_upstream():
                source = "upstream"
                _publish_to_gcs()
            else:
                source = "unavailable"

        _provision_state["attempted"] = True
        _provision_state["source"] = source

    if source == "unavailable":
        logger.warning(
            "No FIDO MDS snapshot is available. Run "
            "'python tools/update_mds_snapshot.py' to create one locally, or "
            "publish one to the configured Cloud Storage bucket."
        )
    elif source != "local":
        logger.info("Provisioned the FIDO MDS snapshot from %s.", source)

    return source


def _pointer_check_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get(_POINTER_CHECK_ENV, _DEFAULT_POINTER_CHECK_SECONDS)))
    except ValueError:
        return _DEFAULT_POINTER_CHECK_SECONDS


def _local_snapshot_no() -> int | None:
    try:
        meta = json.loads(snapshot_path(mds_files.VERIFIED_META).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    no = meta.get("no") if isinstance(meta, dict) else None
    return no if isinstance(no, int) else None


def follow_newer_snapshot() -> bool:
    """Take the set the bucket's pointer names when it is newer than the local
    snapshot; return whether it did.

    A running instance otherwise keeps the snapshot it started with for as long
    as it lives. Called in a request (Cloud Run gives CPU only to requests), at most
    once per ``FIDO_SERVER_MDS_POINTER_CHECK_SECONDS`` (15 minutes): one short read
    of the pointer. The one request that finds a newer set downloads it and writes
    it, payloads first and metas last; every other request meanwhile goes on with
    the snapshot it has, and never waits. Any failure keeps the local snapshot.
    """

    if not cloud.gcs_enabled() or not _follow_lock.acquire(blocking=False):
        return False
    try:
        now = time.monotonic()
        checked_at = _follow_state["checked_at"]
        if checked_at is not None and now - checked_at < _pointer_check_seconds():
            return False
        _follow_state["checked_at"] = now

        pointer, _generation = snapshot_sets.read_pointer(timeout=_POINTER_TIMEOUT_SECONDS, attempts=1)
        if not snapshot_sets.usable(pointer):
            return False
        local_no = _local_snapshot_no()
        if local_no is not None and pointer["no"] <= local_no:
            return False
        files = snapshot_sets.download_set(pointer, timeout=_SET_TIMEOUT_SECONDS)
        _write_set(files)
        _provision_state["source"] = "gcs"
        logger.info("Took MDS snapshot no. %s from Cloud Storage (was %s).", pointer["no"], local_no)
        return True
    except Exception as exc:
        logger.warning("Could not follow the MDS snapshot pointer in Cloud Storage: %s", exc)
        return False
    finally:
        _follow_lock.release()


def waits_for_the_snapshot(view):
    """A route that reads the MDS snapshot waits for a provisioning under way.

    A cold instance provisions the snapshot in the background (about 20 s from
    Cloud Storage, ``startup.start_background_warmup``); until that finishes the
    route would answer as if there were no snapshot. The MDS routes read it, and
    so does a registration's own lookup of its authenticator (the attestation
    checks' root validation and metadata entry), which would otherwise record,
    for good, that no metadata was available. ``ensure_snapshot_available``
    waits on the provisioning's lock, and after the first attempt returns at once.
    """

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        ensure_snapshot_available()
        return view(*args, **kwargs)

    return wrapper
