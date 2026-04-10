"""Environment and cleanup interval helpers for metadata runtime."""
from __future__ import annotations


def _env_flag(name: str) -> Optional[bool]:
    return parse_env_flag(name)


def _resolve_cleanup_interval() -> timedelta:
    raw_seconds = os.environ.get(_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV)
    if raw_seconds is not None:
        try:
            seconds = float(raw_seconds)
            if seconds >= 0:
                return timedelta(seconds=seconds)
        except ValueError:
            app.logger.warning(
                "Invalid value for %s: %r",
                _SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV,
                raw_seconds,
            )

    raw_hours = os.environ.get(_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV)
    if raw_hours is not None:
        try:
            hours = float(raw_hours)
            if hours >= 0:
                return timedelta(hours=hours)
        except ValueError:
            app.logger.warning(
                "Invalid value for %s: %r",
                _SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV,
                raw_hours,
            )

    return timedelta(hours=6)


def _cleanup_async_enabled() -> bool:
    explicit = _env_flag(_SESSION_METADATA_CLEANUP_ASYNC_ENV)
    if explicit is None:
        return True
    return explicit
