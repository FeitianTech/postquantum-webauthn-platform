"""Helpers to warm up dependencies before the server begins serving traffic."""

from __future__ import annotations

from . import cloud_storage, mds_auto_update, session_metadata_store, storage
from .config import app

__all__ = ["warm_up_dependencies"]

_STARTUP_SESSION_ID = "__startup__"


def warm_up_dependencies(*, skip_if_reloader_parent: bool = False) -> None:
    """Run lightweight checks that ensure critical dependencies are ready."""

    app.logger.info("Performing server startup checks.")

    try:
        from .routes.general import ensure_metadata_bootstrapped

        ensure_metadata_bootstrapped(skip_if_reloader_parent=skip_if_reloader_parent)
    except Exception:
        app.logger.exception("Failed to bootstrap FIDO metadata during startup.")
        raise

    # Verify local storage is accessible
    try:
        cloud_storage.ensure_ready()
    except Exception:
        app.logger.exception("Failed to verify local storage readiness during startup.")
        raise

    try:
        session_metadata_store.ensure_session(_STARTUP_SESSION_ID)
        session_metadata_store.touch_last_access(_STARTUP_SESSION_ID)
        storage.list_credentials(session_id=_STARTUP_SESSION_ID)
    except Exception:
        app.logger.exception("Failed to verify session storage readiness during startup.")
        raise
    finally:
    try:
        session_metadata_store.delete_session(_STARTUP_SESSION_ID)
    except Exception:
        app.logger.warning(
            "Failed to clean up startup session %s.",
            _STARTUP_SESSION_ID,
            exc_info=True,
        )

    try:
        mds_auto_update.ensure_mds_auto_update_running(
            skip_if_reloader_parent=skip_if_reloader_parent
        )
    except Exception:
        app.logger.exception("Failed to start FIDO MDS auto-update thread.")
