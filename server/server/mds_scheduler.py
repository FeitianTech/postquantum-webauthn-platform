"""Background scheduler for refreshing the verified FIDO MDS cache."""
from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Optional

from server.scripts import update_mds_cache
from .metadata import load_metadata_cache_entry

_TARGET_HOUR_UTC = 18
_RETRY_INTERVAL = timedelta(minutes=30)

_scheduler_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_state_lock = threading.Lock()
_last_successful_update: Optional[datetime] = None


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    else:
        parsed = parsed.astimezone(UTC)
    return parsed


def _load_last_success_time() -> Optional[datetime]:
    cache_state = load_metadata_cache_entry()
    for key in ("fetched_at", "last_modified_iso", "last_modified"):
        last = _parse_timestamp(cache_state.get(key))
        if last is not None:
            return last
    return None


def _next_scheduled_run(reference: datetime) -> datetime:
    target = reference.astimezone(UTC).replace(
        hour=_TARGET_HOUR_UTC, minute=0, second=0, microsecond=0
    )
    if reference.astimezone(UTC) >= target:
        target += timedelta(days=1)
    return target


def _is_update_due(now: datetime) -> bool:
    with _state_lock:
        last_success = _last_successful_update

    today_target = now.astimezone(UTC).replace(
        hour=_TARGET_HOUR_UTC, minute=0, second=0, microsecond=0
    )
    if now.astimezone(UTC) < today_target:
        return False

    if last_success is None:
        return True

    return last_success < today_target


def _mark_success(timestamp: datetime) -> None:
    with _state_lock:
        global _last_successful_update
        _last_successful_update = timestamp.astimezone(UTC)


def _scheduler_loop(logger: logging.Logger) -> None:
    logger.info("Starting internal FIDO MDS update scheduler.")
    while not _stop_event.is_set():
        now = datetime.now(UTC)

        if _is_update_due(now):
            logger.info("Beginning scheduled FIDO MDS metadata refresh.")
            outcome = update_mds_cache.perform_update(logger=logger)
            if outcome.success:
                _mark_success(datetime.now(UTC))
                next_run = _next_scheduled_run(datetime.now(UTC))
                sleep_for = max((next_run - datetime.now(UTC)).total_seconds(), 60.0)
                logger.info(
                    "FIDO MDS metadata refresh finished. Next run scheduled for %s.",
                    next_run.isoformat(),
                )
            else:
                sleep_for = max(_RETRY_INTERVAL.total_seconds(), 60.0)
                logger.warning(
                    "FIDO MDS metadata refresh failed; retrying in %.0f minutes.",
                    sleep_for / 60,
                )
        else:
            next_run = _next_scheduled_run(now)
            sleep_for = max((next_run - now).total_seconds(), 60.0)
            logger.debug(
                "FIDO MDS metadata refresh not yet due. Next run at %s.",
                next_run.isoformat(),
            )

        _stop_event.wait(sleep_for)

    logger.info("Stopping internal FIDO MDS update scheduler.")


def start_scheduler(logger: logging.Logger) -> None:
    """Launch the background scheduler thread if not already running."""

    global _scheduler_thread

    if _scheduler_thread and _scheduler_thread.is_alive():
        return

    with _state_lock:
        global _last_successful_update
        _last_successful_update = _load_last_success_time()

    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop, args=(logger,), name="mds-update-scheduler", daemon=True
    )
    _scheduler_thread.start()


def stop_scheduler() -> None:
    """Request the scheduler thread to stop (primarily for tests)."""

    _stop_event.set()
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=5)
