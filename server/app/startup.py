"""Helpers to warm up dependencies before the server begins serving traffic."""

from __future__ import annotations

import logging
import os
import threading

from .env_flags import parse_env_flag
from .mds import cache as mds_cache
from .mds import provisioning as mds_provisioning
from .mds import verifier as mds_verifier
from .storage import cloud, common

logger = logging.getLogger(__name__)

__all__ = ["start_background_warmup"]

_BACKGROUND_WARMUP_ENV = "FIDO_SERVER_BACKGROUND_WARMUP"


def background_warmup_enabled() -> bool:
    """Return ``True`` when caches should be warmed after the worker starts."""

    explicit = parse_env_flag(_BACKGROUND_WARMUP_ENV)
    if explicit is not None:
        return explicit
    # Cloud Run sets K_SERVICE; local development keeps lazy loading.
    return bool(os.environ.get("K_SERVICE"))


def _run_background_warmup() -> None:
    if common.using_gcs():
        try:
            cloud._ensure_bucket()
        except Exception:
            logger.warning("Background cloud storage warm-up failed.", exc_info=True)

    # The MDS snapshot is provisioned at runtime rather than shipped in the
    # image, so a cold instance fetches it here instead of on the first request.
    try:
        mds_provisioning.ensure_snapshot_available()
    except Exception:
        logger.warning("Background MDS snapshot provisioning failed.", exc_info=True)

    try:
        # The explorer's files first: every page fetches the list once its
        # first view is interactive. Then the index a registration's metadata
        # lookup reads: the verified entries' JSON, none of it parsed into
        # fido2's dataclasses (mds/verifier.py).
        mds_cache.load_explorer_files()
        mds_verifier.get_mds_verifier()
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
