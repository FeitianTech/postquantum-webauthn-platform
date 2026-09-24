"""``create_app()``: build and configure the Flask application.

Nothing here runs on import. ``create_app`` builds a fresh app, puts the settings
read from the environment into ``app.config`` followed by the caller's
overrides, then runs ``INIT_STEPS`` in order. ``tests/app/core/test_app_factory.py``
pins that order.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from flask import Flask

from . import static_assets
from .config import (
    application,
    attestation_trust,
    compression,
    logs,
    mds,
    origins,
    proxy,
    relying_party,
    security_headers,
    session_cookie,
    session_secret,
)
from .routes import advanced, errors, general, simple

__all__ = ["INIT_STEPS", "create_app"]

# Each supplies ``config_from_env()``: settings read from the environment.
CONFIG_SOURCES = (
    attestation_trust,
    origins,
    relying_party,
    security_headers,
    session_cookie,
    mds,
)


def _register_blueprints(app: Flask) -> None:
    for blueprint in (advanced.bp, general.bp, simple.bp):
        app.register_blueprint(blueprint)
    errors.init_app(app)


# The order matters:
# - logs first, so nothing that follows can log before the handler exists;
# - the secret before anything could open a session;
# - Flask runs after_request handlers in reverse registration order, so
#   compression is registered before security_headers and runs after it: the
#   headers are set on the response before its body is gzipped.
INIT_STEPS: tuple[Callable[[Flask], None], ...] = (
    logs.init_app,
    session_secret.init_app,
    proxy.init_app,
    compression.init_app,
    security_headers.init_app,
    static_assets.init_app,
    _register_blueprints,
    relying_party.init_app,
)


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    """Return a new, fully configured app.

    ``config`` overrides anything read from the environment. A ``SECRET_KEY`` in
    it is used as is, so nothing is read from or written to the instance folder.
    """

    app = application.build_app()
    for source in CONFIG_SOURCES:
        app.config.update(source.config_from_env())
    if config:
        app.config.update(config)
    for step in INIT_STEPS:
        step(app)
    return app
