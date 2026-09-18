"""Runtime provisioning of the packaged FIDO MDS snapshot.

The snapshot is a ~30 MB set of generated files (the signed BLOB, the verified
payload and the explorer views). It is not tracked in git and is not baked into
the container image, so a daily refresh no longer rewrites repository history or
invalidates a Docker layer. Instead the files are materialised into
``frontend/static`` on demand, in three tiers:

1. **Local files.** Anything already on disk is used as-is. This is the path a
   developer gets after running ``python tools/update_mds_snapshot.py`` once,
   and it is the only tier that needs no network access at all.
2. **Cloud Storage.** When GCS is configured (``FIDO_SERVER_GCS_ENABLED``), the
   missing files are downloaded from ``<bucket>/mds/``. This is how a Cloud Run
   cold start gets the snapshot without shipping it in the image.
3. **Upstream refresh.** As a last resort the packaged updater is run, which
   downloads the BLOB from the FIDO Alliance and verifies it against the pinned
   trust root before writing anything. The result is uploaded to Cloud Storage
   so the next cold start stops at tier 2.

Tier 3 is opt-in through ``FIDO_SERVER_MDS_FETCH_UPSTREAM`` and defaults to the
GCS setting: on by default in a deployed service, off by default locally so a
first request never blocks on a 10 MB download. With every tier unavailable the
application still starts and serves; the metadata APIs report that no snapshot
is available, exactly as they already did for a missing snapshot.
"""
from __future__ import annotations

import gzip
import os
import threading
from pathlib import Path

from . import cloud_storage
from .config import _FRONTEND_STATIC_ROOT, app
from .env_flags import parse_env_flag

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
# check in metadata/base_snapshot_runtime.py compare mismatched snapshots.
SNAPSHOT_FILENAMES = (
    "blob.jwt",
    "fido-mds3.verified.json",
    "fido-mds3.verified.json.meta.json",
    "fido-mds3.explorer.json",
    "fido-mds3.explorer.json.meta.json",
    "fido-mds3.explorer.full.json",
    "fido-mds3.explorer.full.json.meta.json",
)

# Browsers fetch the full explorer snapshot as a versioned static asset, so it
# needs the precompressed sibling that tools/build_static_assets.py would have
# written at image build time had the file been present then.
PRECOMPRESSED_FILENAMES = frozenset({"fido-mds3.explorer.full.json"})
_MIN_COMPRESS_BYTES = 1024

_DEFAULT_BLOB_PREFIX = "mds"
_BLOB_PREFIX_ENV = "FIDO_SERVER_MDS_GCS_PREFIX"
_UPSTREAM_ENV_FLAG = "FIDO_SERVER_MDS_FETCH_UPSTREAM"

_provision_lock = threading.Lock()
_provision_state: dict[str, object] = {"attempted": False, "source": None}


def snapshot_path(filename: str) -> Path:
    return Path(_FRONTEND_STATIC_ROOT) / filename


def snapshot_blob_name(filename: str) -> str:
    prefix = os.environ.get(_BLOB_PREFIX_ENV, _DEFAULT_BLOB_PREFIX)
    return cloud_storage.build_blob_name(filename, prefix=prefix)


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
    return cloud_storage.gcs_enabled()


def write_snapshot_file(filename: str, data: bytes) -> Path:
    """Write one snapshot file, plus its .gz sibling where browsers need one."""

    path = snapshot_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written via a temporary file so a reader never observes a partial snapshot.
    temporary = path.with_name(f"{path.name}.partial")
    temporary.write_bytes(data)
    temporary.replace(path)

    if filename in PRECOMPRESSED_FILENAMES and len(data) >= _MIN_COMPRESS_BYTES:
        compressed = gzip.compress(data, compresslevel=9, mtime=0)
        if len(compressed) < len(data):
            gzip_temporary = path.with_name(f"{path.name}.gz.partial")
            gzip_temporary.write_bytes(compressed)
            gzip_temporary.replace(path.with_name(f"{path.name}.gz"))

    return path


def _download_from_gcs(missing: tuple[str, ...]) -> tuple[str, ...]:
    """Fetch ``missing`` from Cloud Storage; return the names still missing."""

    if not cloud_storage.gcs_enabled():
        return missing

    remaining: list[str] = []
    for filename in missing:
        try:
            data = cloud_storage.download_bytes(snapshot_blob_name(filename))
        except Exception as exc:  # pragma: no cover - network/credential failure
            app.logger.warning(
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
        try:
            import update_mds_snapshot  # type: ignore[no-redef]
        except ImportError:
            app.logger.warning(
                "The MDS snapshot updater is not packaged with this build; "
                "cannot refresh the snapshot from the FIDO Alliance."
            )
            return False

    try:
        return update_mds_snapshot.main() == 0
    except Exception as exc:  # pragma: no cover - network/parse failure
        app.logger.warning("Refreshing the MDS snapshot from upstream failed: %s", exc)
        return False


def _upload_to_gcs(filenames: tuple[str, ...]) -> None:
    if not cloud_storage.gcs_enabled():
        return

    for filename in filenames:
        path = snapshot_path(filename)
        if not path.is_file():
            continue
        try:
            cloud_storage.upload_bytes(
                snapshot_blob_name(filename),
                path.read_bytes(),
                content_type="application/json" if filename.endswith(".json") else None,
            )
        except Exception as exc:  # pragma: no cover - network/credential failure
            app.logger.warning(
                "Could not publish MDS snapshot file %s to Cloud Storage: %s",
                filename,
                exc,
            )


def ensure_snapshot_available(*, force: bool = False) -> str:
    """Materialise the MDS snapshot into ``frontend/static``.

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
            app.logger.info(
                "MDS snapshot files missing locally (%s); provisioning.",
                ", ".join(missing),
            )
            still_missing = _download_from_gcs(missing)
            if not still_missing:
                source = "gcs"
            elif upstream_refresh_enabled() and _refresh_from_upstream():
                source = "upstream"
                _upload_to_gcs(SNAPSHOT_FILENAMES)
            else:
                source = "unavailable"

        _provision_state["attempted"] = True
        _provision_state["source"] = source

    if source == "unavailable":
        app.logger.warning(
            "No FIDO MDS snapshot is available. Run "
            "'python tools/update_mds_snapshot.py' to create one locally, or "
            "publish one to the configured Cloud Storage bucket."
        )
    elif source != "local":
        app.logger.info("Provisioned the FIDO MDS snapshot from %s.", source)

    return source
