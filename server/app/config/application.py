"""The bare Flask object that ``create_app()`` configures.

The app is named ``server.app`` so that ``app.logger`` is the parent of every
module's ``logging.getLogger(__name__)``: their records propagate to the handler
Flask gives ``app.logger`` (see ``logs``). The instance folder is fixed rather
than derived from the name, so the session secret and the local credential
store stay where they are. It has no static rule and no templates of its own:
the site's pages and their files are the UI's static export, which
``routes/web_export.py`` serves from ``/`` (its catch-all takes the place Flask's
static rule had). ``add_after_request_once`` registers a response handler that
must run once however often ``init_app`` is called.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask

from .paths import INSTANCE_ROOT, basepath


def build_app() -> Flask:
    """Return a new, unconfigured Flask app rooted at ``server/app``."""

    return Flask(
        "server.app",
        root_path=basepath,
        instance_path=INSTANCE_ROOT,
        static_folder=None,
        template_folder=None,
    )


def add_after_request_once(flask_app: Flask, handler: Callable[[Any], Any], marker: str) -> None:
    """Run ``handler`` after each request, unless a handler carrying ``marker`` already does.

    Only before the app's first request: Flask refuses a handler added later.
    """

    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, marker, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)
