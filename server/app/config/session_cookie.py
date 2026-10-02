"""The Flask session cookie's flags and lifetime, which ``create_app()`` applies,
and the session interface that keeps the files' answers from setting it."""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from flask import Flask, has_request_context, request
from flask.sessions import SecureCookieSessionInterface

from ..env_flags import parse_env_flag
from . import proxy

# Session state here is short-lived ceremony state (WebAuthn challenges and the
# metadata-session pointer), not a signed-in user session, so the 31-day Flask
# default is far longer than anything needs to live.
_DEFAULT_SESSION_LIFETIME_SECONDS = 30 * 60


def _resolve_session_lifetime_seconds() -> int:
    raw = os.environ.get("FIDO_SERVER_SESSION_LIFETIME_SECONDS")
    if raw:
        try:
            parsed = int(float(raw.strip()))
        except (TypeError, ValueError):
            return _DEFAULT_SESSION_LIFETIME_SECONDS
        if parsed > 0:
            return parsed
    return _DEFAULT_SESSION_LIFETIME_SECONDS


def _resolve_session_cookie_secure() -> bool:
    """Return the ``Secure`` flag for the Flask session cookie.

    A ``Secure`` cookie is never sent back over ``http://``, which would break
    both localhost development and the Werkzeug test client, so this defaults to
    ``True`` only where TLS is known to be terminated in front of the app.
    ``FIDO_SERVER_SESSION_COOKIE_SECURE`` forces it either way for deployments
    behind some other HTTPS proxy.
    """

    explicit = parse_env_flag("FIDO_SERVER_SESSION_COOKIE_SECURE")
    if explicit is not None:
        return explicit
    return proxy._running_behind_managed_proxy()


def config_from_env() -> dict[str, Any]:
    """The cookie settings ``create_app()`` puts into ``app.config``.

    They replace Flask's own defaults for the same keys.
    """

    return {
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SECURE": _resolve_session_cookie_secure(),
        # WebAuthn ceremonies are same-site fetches from our own page, so "Lax"
        # costs nothing and keeps the cookie off cross-site POSTs.
        "SESSION_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": timedelta(seconds=_resolve_session_lifetime_seconds()),
    }


# The blueprints that serve files: the UI's export at / (routes/web_export.py)
# and the MDS snapshot's files (routes/assets.py). Neither reads the session.
_FILE_BLUEPRINTS = frozenset({"web_export", "assets"})


class FileQuietSessionInterface(SecureCookieSessionInterface):
    """Flask's signed-cookie session, whose cookie a file's answer never refreshes.

    Flask sets a permanent session's cookie again on every answer, from the
    session as that request found it. A file fetched while a ceremony runs (a
    script chunk, the MDS list, an icon) could then answer after the ceremony's
    begin and put back the cookie from before it, without the state begin kept,
    and the ceremony's complete would fail. A file's answer leaves the cookie
    as it is, unless the session changed (files never change it).
    """

    def should_set_cookie(self, app: Flask, session: Any) -> bool:
        if not session.modified and has_request_context() and request.blueprint in _FILE_BLUEPRINTS:
            return False
        return super().should_set_cookie(app, session)


def init_app(app: Flask) -> None:
    """Use the session interface that leaves the cookie alone for files."""

    app.session_interface = FileQuietSessionInterface()
