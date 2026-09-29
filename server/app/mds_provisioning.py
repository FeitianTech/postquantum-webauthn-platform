"""Runtime provisioning of the packaged FIDO MDS snapshot.

The snapshot is a ~30 MB set of generated files (the signed BLOB, the verified
payload and the explorer views). It is not tracked in git and is not baked into
the container image, so a daily refresh no longer rewrites repository history or
invalidates a Docker layer. Instead the files are materialised into
the snapshot directory (``instance/mds-snapshot`` unless
``FIDO_SERVER_MDS_SNAPSHOT_DIR`` names another, ``server.app.mds_snapshot_dir``) on
demand, in three tiers:

1. **Local files.** Anything already on disk is used as-is. This is the path a
   developer gets after running ``python tools/update_mds_snapshot.py`` once,
   and it is the only tier that needs no network access at all.
2. **Cloud Storage.** When GCS is configured (``FIDO_SERVER_GCS_ENABLED``), the
   set ``<bucket>/mds/current.json`` points to is downloaded, each file checked
   against the pointer (``mds_snapshot_sets``); without a usable one, the files
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
import logging
import os
import threading
from pathlib import Path

from . import mds_snapshot_dir, mds_snapshot_sets
from .env_flags import parse_env_flag
from .storage import cloud

logger = logging.getLogger(__name__)

__all__ = [
    "SNAPSHOT_FILENAMES",
    "ensure_snapshot_available",
    "missing_snapshot_files",
    "snapshot_blob_name",
    "upstream_refresh_enabled",
    "write_snapshot_file",
]

# Every file tools/update_mds_snapshot.py writes, in one set. The payloads and
# their .meta.json companions are generated together and describe each other, so
# they are provisioned together too; mixing generations would make the freshness
# check in metadata/blob.py compare mismatched snapshots.
SNAPSHOT_FILENAMES = mds_snapshot_dir.SNAPSHOT_FILENAMES


_DEFAULT_BLOB_PREFIX = "mds"
_BLOB_PREFIX_ENV = "FIDO_SERVER_MDS_GCS_PREFIX"
_UPSTREAM_ENV_FLAG = "FIDO_SERVER_MDS_FETCH_UPSTREAM"

_provision_lock = threading.Lock()
_provision_state: dict[str, object] = {"attempted": False, "source": None}


def snapshot_path(filename: str) -> Path:
    return mds_snapshot_dir.snapshot_file(filename)


def snapshot_blob_name(filename: str) -> str:
    prefix = os.environ.get(_BLOB_PREFIX_ENV, _DEFAULT_BLOB_PREFIX)
    return cloud.build_blob_name(filename, prefix=prefix)


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
    """Write one snapshot file, plus its .gz sibling where browsers need one."""

    path = snapshot_path(filename)
    mds_snapshot_dir.write_file(path, data)
    return path


def _write_set(files: dict[str, bytes]) -> None:
    """Write a complete set, payloads first and metas last (``WRITE_ORDER``)."""

    for filename in mds_snapshot_dir.WRITE_ORDER:
        write_snapshot_file(filename, files[filename])


def _download_set_from_gcs() -> dict | None:
    """Fetch the set the bucket's pointer names; return the pointer, or None
    when there is no usable pointer or its set cannot be read whole."""

    if not cloud.gcs_enabled():
        return None
    try:
        pointer, _generation = mds_snapshot_sets.read_pointer()
        if not mds_snapshot_sets.usable(pointer):
            return None
        files = mds_snapshot_sets.download_set(pointer)
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
        result = mds_snapshot_sets.publish(files)
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
