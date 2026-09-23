"""The Flask application singleton.

Every other config submodule configures this one object as it is imported; the
re-import guard keeps it the same object if this module is reloaded.

The app is named ``server.app`` so that ``app.logger`` is the parent of every
module's ``logging.getLogger(__name__)``: their records propagate to the stderr
handler Flask gives ``app.logger`` (see the read of it below).
"""
from __future__ import annotations

from flask import Flask

from .paths import (
    _FRONTEND_STATIC_ROOT,
    _FRONTEND_TEMPLATE_ROOT,
    INSTANCE_ROOT,
    basepath,
)

_existing_app = globals().get("app")
if isinstance(_existing_app, Flask):
    app = _existing_app
else:
    # Rooted at server/app. The name is also the logger's name.
    app = Flask(
        "server.app",
        root_path=basepath,
        instance_path=INSTANCE_ROOT,
        static_folder=str(_FRONTEND_STATIC_ROOT),
        static_url_path="",
        template_folder=str(_FRONTEND_TEMPLATE_ROOT),
    )
    # Flask attaches its stderr handler to app.logger the first time it is read,
    # unless a handler for its level is already configured. Read it before
    # anything logs, so module loggers never fall through to logging.lastResort.
    app.logger
