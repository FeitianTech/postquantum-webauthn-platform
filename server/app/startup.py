"""Helpers to warm up dependencies before the server begins serving traffic."""

from __future__ import annotations

import os
from typing import Optional

from . import cloud_storage, session_metadata_store
from .config import app
from .env_flags import parse_env_flag

__all__ = ["warm_up_dependencies"]

_STARTUP_SESSION_ID = "__startup__"
_STARTUP_MODE_ENV = "FIDO_SERVER_STARTUP_MODE"
_STARTUP_FAIL_FAST_ENV = "FIDO_SERVER_STARTUP_FAIL_FAST"
_WARM_METADATA_ENV = "FIDO_SERVER_WARM_METADATA"
_WARM_CLOUD_STORAGE_ENV = "FIDO_SERVER_WARM_CLOUD_STORAGE"
_WARM_SESSION_STORAGE_ENV = "FIDO_SERVER_WARM_SESSION_STORAGE"


def _env_flag(name: str) -> Optional[bool]:
    return parse_env_flag(name)


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


def _should_warm_metadata(*, fail_fast: bool) -> bool:
    explicit = _env_flag(_WARM_METADATA_ENV)
    if explicit is not None:
        return explicit
    return fail_fast


def _should_warm_cloud_storage_for_mode(*, fail_fast: bool) -> bool:
    explicit = _env_flag(_WARM_CLOUD_STORAGE_ENV)
    if explicit is not None:
        return explicit and _should_warm_cloud_storage_configured()
    return fail_fast and _should_warm_cloud_storage_configured()


def _should_warm_cloud_storage_configured() -> bool:
    return cloud_storage.gcs_enabled() and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))


def _should_warm_session_storage(*, fail_fast: bool) -> bool:
    explicit = _env_flag(_WARM_SESSION_STORAGE_ENV)
    if explicit is not None:
        return explicit
    return fail_fast


def _should_warm_cloud_storage() -> bool:
    return _should_warm_cloud_storage_configured()


def warm_up_dependencies(
    *,
    skip_if_reloader_parent: bool = False,
    fail_fast: Optional[bool] = None,
) -> None:
    """Run lightweight checks that ensure critical dependencies are ready."""

    effective_fail_fast = startup_fail_fast_enabled() if fail_fast is None else bool(fail_fast)
    startup_mode = "strict" if effective_fail_fast else "fast"

    app.logger.info("Performing server startup checks (mode=%s).", startup_mode)

    def _handle_failure(message: str) -> None:
        if effective_fail_fast:
            app.logger.exception(message)
            raise
        app.logger.warning(message, exc_info=True)

    if _should_warm_metadata(fail_fast=effective_fail_fast):
        try:
            from .routes.general import ensure_metadata_bootstrapped

            ensure_metadata_bootstrapped(skip_if_reloader_parent=skip_if_reloader_parent)
        except Exception:
            _handle_failure("Failed to bootstrap FIDO metadata during startup.")
    else:
        app.logger.info(
            "Skipping startup metadata bootstrap; metadata will load lazily on demand."
        )

    if _should_warm_cloud_storage_for_mode(fail_fast=effective_fail_fast):
        try:
            cloud_storage.ensure_ready()
        except Exception:
            _handle_failure("Failed to verify Google Cloud Storage readiness during startup.")
    elif _should_warm_cloud_storage_configured():
        app.logger.info(
            "Skipping startup Google Cloud Storage readiness check; storage will be verified lazily."
        )

    if _should_warm_session_storage(fail_fast=effective_fail_fast):
        try:
            session_metadata_store.ensure_session(_STARTUP_SESSION_ID)
            session_metadata_store.touch_last_access(_STARTUP_SESSION_ID)
        except Exception:
            _handle_failure("Failed to verify session storage readiness during startup.")
        finally:
            try:
                session_metadata_store.delete_session(_STARTUP_SESSION_ID)
            except Exception:
                app.logger.warning(
                    "Failed to clean up startup session %s.",
                    _STARTUP_SESSION_ID,
                    exc_info=True,
                )
    else:
        app.logger.info(
            "Skipping startup session storage probe; storage health checks will run lazily."
        )
