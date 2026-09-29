"""Helpers to warm up dependencies before the server begins serving traffic."""

from __future__ import annotations

import logging
import os
import threading

from .env_flags import parse_env_flag
from .storage import cloud

logger = logging.getLogger(__name__)

__all__ = ["start_background_warmup"]

_STARTUP_MODE_ENV = "FIDO_SERVER_STARTUP_MODE"
_STARTUP_FAIL_FAST_ENV = "FIDO_SERVER_STARTUP_FAIL_FAST"
_BACKGROUND_WARMUP_ENV = "FIDO_SERVER_BACKGROUND_WARMUP"


def _env_flag(name: str) -> bool | None:
    return parse_env_flag(name)


def background_warmup_enabled() -> bool:
    """Return ``True`` when caches should be warmed after the worker starts."""

    explicit = _env_flag(_BACKGROUND_WARMUP_ENV)
    if explicit is not None:
        return explicit
    # Cloud Run sets K_SERVICE; local development keeps lazy loading.
    return bool(os.environ.get("K_SERVICE"))


def _run_background_warmup() -> None:
    if _should_warm_cloud_storage_configured():
        try:
            cloud._ensure_bucket()
        except Exception:
            logger.warning("Background cloud storage warm-up failed.", exc_info=True)

    # The MDS snapshot is provisioned at runtime rather than shipped in the
    # image, so a cold instance fetches it here instead of on the first request.
    try:
        from .mds_provisioning import ensure_snapshot_available

        ensure_snapshot_available()
    except Exception:
        logger.warning("Background MDS snapshot provisioning failed.", exc_info=True)

    try:
        from .webauthn.metadata import load_cached_metadata_snapshot

        load_cached_metadata_snapshot()
    except Exception:
        logger.warning("Background metadata warm-up failed.", exc_info=True)


def start_background_warmup() -> threading.Thread | None:
    """Warm slow dependencies without delaying the worker from serving requests.

    Requests that need the same data while warm-up runs wait on the shared cache
    locks instead of loading it a second time.
    """

    if not background_warmup_enabled():
        return None

    thread = threading.Thread(
        target=_run_background_warmup, name="startup-warmup", daemon=True
    )
    thread.start()
    return thread


def startup_fail_fast_enabled() -> bool:
    """Return ``True`` when startup warmup failures should block serving traffic."""

    explicit = _env_flag(_STARTUP_FAIL_FAST_ENV)
    if explicit is not None:
        return explicit

    mode = (os.environ.get(_STARTUP_MODE_ENV) or "").strip().lower()
    if mode in {"strict", "fail-fast", "fail_fast", "blocking"}:
        return True
    if mode in {"fast", "lazy", "non-blocking", "non_blocking"}:
        return False

    # Fast startup is the default on Cloud Run to reduce cold-start latency.
    return False


def _should_warm_cloud_storage_configured() -> bool:
    return cloud.gcs_enabled() and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))
