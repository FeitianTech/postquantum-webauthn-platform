"""The Flask session cookie's flags and lifetime, which ``create_app()`` applies,
and the size the session's cookie would take."""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from flask import Flask
from flask.sessions import SessionMixin
from werkzeug.http import dump_cookie

from ..env_flags import parse_env_flag
from . import proxy

# Session state here is short-lived ceremony state (a WebAuthn ceremony's, from
# its begin to its complete), not a signed-in user session, so the 31-day Flask
# default is far longer than anything needs to live. Flask refuses a session
# cookie signed longer ago than this, permanent or not.
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
        # The cookie is set only by an answer that changed the session: a ceremony's.
        # Flask would otherwise set a permanent session's cookie (one an earlier
        # release made) on every answer, from the session that request saw, and an
        # answer that landed after a ceremony's begin would undo the state begin kept.
        "SESSION_REFRESH_EACH_REQUEST": False,
    }


def cookie_size(app: Flask, session: SessionMixin) -> int:
    """The length of the Set-Cookie header the session interface would send for ``session``.

    Werkzeug warns past ``MAX_COOKIE_SIZE`` (4,093 by default); a browser drops a
    cookie whose name and value pass 4,096 bytes and keeps the one it had.
    """

    interface = app.session_interface
    serializer = interface.get_signing_serializer(app)  # type: ignore[attr-defined]
    return len(
        dump_cookie(
            interface.get_cookie_name(app),
            serializer.dumps(dict(session)),
            expires=interface.get_expiration_time(app, session),
            path=interface.get_cookie_path(app),
            domain=interface.get_cookie_domain(app),
            secure=interface.get_cookie_secure(app),
            httponly=interface.get_cookie_httponly(app),
            samesite=interface.get_cookie_samesite(app),
            partitioned=interface.get_cookie_partitioned(app),
            max_size=0,
        )
    )
