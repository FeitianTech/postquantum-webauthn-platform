"""Which ``X-Forwarded-*`` headers to believe, and the ``ProxyFix`` that applies it.

``create_app()`` applies it to ``app.wsgi_app`` with ``init_app``, if the proxy is
trusted.
"""
from __future__ import annotations

import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from ..env_flags import parse_env_flag

_PROXY_FIX_MARKER = "_postquantum_proxy_fix"


def _running_behind_managed_proxy() -> bool:
    """Return ``True`` when the platform terminates TLS in front of this process.

    Cloud Run sets ``K_SERVICE``; the rest of the codebase already treats that as
    the "running on Cloud Run" signal (see ``startup.py`` and ``device_logs.py``).
    """

    return bool(os.environ.get("K_SERVICE"))


def _should_trust_proxy_headers() -> bool:
    """Return ``True`` when ``X-Forwarded-*`` headers may be believed."""

    explicit = parse_env_flag("FIDO_SERVER_TRUST_PROXY")
    if explicit is not None:
        return explicit
    return _running_behind_managed_proxy()


def _apply_proxy_fix(flask_app: Flask) -> bool:
    """Honour the forwarded scheme/client IP, but never the forwarded host.

    Cloud Run speaks plain HTTP to the container, so ``request.is_secure`` and
    ``request.scheme`` are wrong -- HSTS would never be emitted and a ``Secure``
    session cookie would look unnecessary -- unless ``X-Forwarded-Proto`` is
    honoured.

    ``x_host``, ``x_port`` and ``x_prefix`` are deliberately left at ``0``.  When
    no ``FIDO_SERVER_RP_ID`` is configured this app derives the WebAuthn RP ID
    from the request ``Host`` header (``determine_rp_id`` ->
    ``_resolve_request_host``), and ``request.headers["Host"]`` is a live view of
    ``environ["HTTP_HOST"]`` -- precisely the value ``ProxyFix(x_host=1)``
    overwrites from the client-supplied ``X-Forwarded-Host``.  Trusting it would
    hand an attacker control of the RP ID and of the expected origin derived from
    ``request.host_url``, reintroducing the Host-header injection the RP ID
    configuration exists to prevent.  Cloud Run forwards the original ``Host``
    unchanged, so only the scheme and the client IP need correcting.
    """

    if getattr(flask_app.wsgi_app, _PROXY_FIX_MARKER, False):
        return False

    wrapped = ProxyFix(
        flask_app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=0,
        x_port=0,
        x_prefix=0,
    )
    setattr(wrapped, _PROXY_FIX_MARKER, True)
    flask_app.wsgi_app = wrapped
    return True


def init_app(app: Flask) -> None:
    """Wrap ``app.wsgi_app`` in ``ProxyFix`` when the forwarded headers are trusted."""

    if _should_trust_proxy_headers():
        _apply_proxy_fix(app)
