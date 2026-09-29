"""Where module log records go: through the app's logger to stderr.

Every module logs through ``logging.getLogger(__name__)``, a child of
``app.logger`` (``server.app``). Flask gives ``app.logger`` a handler that writes
to ``wsgi.errors`` inside a request and to stderr otherwise, the first time it
is read -- unless a handler for its level is already configured. Gunicorn
configures no root handler here (``gunicorn.conf.py`` sets no ``logconfig``), so
without that handler module records would fall through to
``logging.lastResort``: unformatted, and WARNING and above only.

fido2's ``Fido2Server`` logs each registered and authenticated credential ID at
INFO. A credential ID identifies a visitor's authenticator, so ``fido2.server``
is held at WARNING whatever handler the root logger gets.
"""
from __future__ import annotations

import logging

from flask import Flask


def init_app(app: Flask) -> None:
    """Attach Flask's handler to ``app.logger`` before anything logs."""

    # Reading the property is what creates the logger and attaches the handler.
    app.logger
    logging.getLogger("fido2.server").setLevel(logging.WARNING)
