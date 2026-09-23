"""The Flask session cookie's flags and lifetime, applied to ``app.config`` on import."""
from __future__ import annotations

import os
from datetime import timedelta

from ..env_flags import parse_env_flag
from . import proxy
from .application import app

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


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=_resolve_session_cookie_secure(),
    # WebAuthn ceremonies are same-site fetches from our own page, so "Lax" costs
    # nothing and keeps the cookie off cross-site POSTs.
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=_resolve_session_lifetime_seconds()),
)
