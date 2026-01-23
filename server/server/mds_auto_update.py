"""Background scheduler for refreshing the FIDO MDS snapshot."""
from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

try:  # pragma: no cover - platform dependent
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

from . import metadata
from .config import (
    MDS_AUTO_UPDATE_ENABLED,
    MDS_AUTO_UPDATE_FORCE_REFRESH,
    MDS_AUTO_UPDATE_INTERVAL_SECONDS,
    app,
)

_AUTO_UPDATE_LOCK = threading.Lock()
_AUTO_UPDATE_THREAD: Optional[threading.Thread] = None


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def _last_checked_date() -> Optional[datetime.date]:
    cache = metadata.load_metadata_cache_entry()
    fetched_at = cache.get("fetched_at")
    parsed = _parse_iso_datetime(fetched_at)
    if parsed is None:
        return None
    return parsed.date()


def _is_check_due() -> bool:
    last_checked = _last_checked_date()
    today = datetime.now(timezone.utc).date()
    return last_checked != today


@contextmanager
def _update_lock() -> Iterator[bool]:
    lock_path = Path(str(metadata.MDS_METADATA_CACHE_PATH) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock_file:
        if fcntl is None:
            yield True
            return
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _run_update_if_due() -> None:
    if not _is_check_due():
        return

    with _update_lock() as acquired:
        if not acquired:
            return
        if not _is_check_due():
            return
        try:
            updated = metadata.refresh_metadata_snapshot(force=MDS_AUTO_UPDATE_FORCE_REFRESH)
        except metadata.MetadataDownloadError as exc:
            if exc.retry_after:
                app.logger.warning(
                    "FIDO MDS auto-update failed (retry-after %s): %s",
                    exc.retry_after,
                    exc,
                )
            else:
                app.logger.warning("FIDO MDS auto-update failed: %s", exc)
            return
        except Exception:
            app.logger.exception("Unexpected error while updating FIDO MDS metadata.")
            return

        if updated:
            app.logger.info("FIDO MDS snapshot refreshed.")
        else:
            app.logger.info("FIDO MDS snapshot already up to date.")


def _auto_update_loop() -> None:
    app.logger.info("Starting FIDO MDS auto-update loop.")
    while True:
        _run_update_if_due()
        time.sleep(MDS_AUTO_UPDATE_INTERVAL_SECONDS)


def ensure_mds_auto_update_running(*, skip_if_reloader_parent: bool = False) -> None:
    if skip_if_reloader_parent and app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    if not MDS_AUTO_UPDATE_ENABLED:
        return

    global _AUTO_UPDATE_THREAD
    with _AUTO_UPDATE_LOCK:
        if _AUTO_UPDATE_THREAD and _AUTO_UPDATE_THREAD.is_alive():
            return
        thread = threading.Thread(
            target=_auto_update_loop,
            name="mds-auto-update",
            daemon=True,
        )
        _AUTO_UPDATE_THREAD = thread
        thread.start()
