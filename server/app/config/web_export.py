"""Where the new UI's static export is: the ``web/out`` that ``next build`` writes.

``create_app()`` puts it in ``app.config["WEB_EXPORT_ROOT"]``, and
``routes/web_export.py`` serves it at ``/beta`` (docs/UI_MIGRATION.md).
``FIDO_SERVER_WEB_EXPORT_ROOT`` points elsewhere. Nothing has to exist there:
without a build, ``/beta`` answers 404 and the rest of the app is unchanged.
In the image the export is at ``/app/web/out`` (the Dockerfile's web stage).
"""
from __future__ import annotations

import os
from typing import Any

from .paths import _PROJECT_ROOT

WEB_EXPORT_ROOT_KEY = "WEB_EXPORT_ROOT"
DEFAULT_WEB_EXPORT_ROOT = _PROJECT_ROOT / "web" / "out"


def config_from_env() -> dict[str, Any]:
    """The export root ``create_app()`` puts into ``app.config``."""

    configured = (os.environ.get("FIDO_SERVER_WEB_EXPORT_ROOT") or "").strip()
    return {WEB_EXPORT_ROOT_KEY: configured or str(DEFAULT_WEB_EXPORT_ROOT)}
