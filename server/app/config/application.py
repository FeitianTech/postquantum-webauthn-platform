"""The bare Flask object that ``create_app()`` configures.

The app is named ``server.app`` so that ``app.logger`` is the parent of every
module's ``logging.getLogger(__name__)``: their records propagate to the handler
Flask gives ``app.logger`` (see ``logs``). The instance folder is fixed rather
than derived from the name, so the session secret and the local credential
store stay where they are. It has no static rule and no templates of its own:
the site's pages and their files are the new UI's export, which
``routes/web_export.py`` serves from ``/`` (its catch-all takes the place Flask's
static rule had).
"""
from __future__ import annotations

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
