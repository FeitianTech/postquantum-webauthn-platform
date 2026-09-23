"""Response security headers: CSP, Permissions-Policy, HSTS and friends.

The defaults land in ``app.config`` and the handler is registered as an
``after_request`` handler when this module is imported. Flask runs those handlers
in reverse, so this one, registered after ``compression``'s, runs before it.
"""
from __future__ import annotations

import os

from flask import Flask, has_request_context, request

from .application import app

_SECURITY_HEADERS_MARKER = "_postquantum_security_headers"

# TODO(csp-strict): drop ``'unsafe-inline'`` from ``script-src`` (ideally moving to
# a per-response nonce) once the inline event handlers are gone.
#
# BLOCKER: ``frontend/templates/**/*.html`` still carries 125 inline ``on*="..."``
# attributes -- concentrated in the advanced registration/authentication option
# panels -- plus the inline ``<script>`` in ``frontend/templates/index.html`` that
# seeds ``window.__INITIAL_MDS_INFO__``.  Inline event handlers cannot be
# nonced; they need either ``'unsafe-inline'`` or ``'unsafe-hashes'`` with a hash
# per handler.  Shipping ``script-src 'self'`` today would dead-stop the UI, so
# the handlers have to be moved into ``frontend/static/scripts`` first.
#
# Be clear about what this buys: with ``'unsafe-inline'`` present the script
# policy blocks third-party script origins, ``eval``/``new Function`` and
# ``javascript:`` URLs, but it does NOT stop an injected inline ``<script>`` or
# ``on*=`` attribute.  It is defence in depth, not XSS containment.  The
# non-script directives below are genuinely strict.
_DEFAULT_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        # Clickjacking a WebAuthn RP lets an attacker drive a real ceremony
        # behind an invisible overlay, so framing is refused outright.
        "frame-ancestors 'none'",
        "frame-src 'none'",
        "form-action 'self'",
        "img-src 'self' data:",
        "font-src 'self' https://fonts.gstatic.com",
        # 5 inline style="" attributes in the templates, plus the Google Fonts
        # stylesheet linked from index.html.
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        # See TODO(csp-strict) above: 125 inline on*= handlers block 'self'-only.
        "script-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
    )
)

_DEFAULT_PERMISSIONS_POLICY = ", ".join(
    (
        "accelerometer=()",
        "autoplay=()",
        "camera=()",
        "display-capture=()",
        "encrypted-media=()",
        "fullscreen=(self)",
        "geolocation=()",
        "gyroscope=()",
        "magnetometer=()",
        "microphone=()",
        "midi=()",
        "payment=()",
        "picture-in-picture=()",
        # The point of the whole app: only this origin may run WebAuthn
        # ceremonies, and no embedded document may run them on our behalf.
        "publickey-credentials-create=(self)",
        "publickey-credentials-get=(self)",
        "screen-wake-lock=()",
        "usb=()",
        "xr-spatial-tracking=()",
    )
)

_DEFAULT_STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains"

app.config.setdefault(
    "CONTENT_SECURITY_POLICY",
    os.environ.get("FIDO_SERVER_CONTENT_SECURITY_POLICY")
    or _DEFAULT_CONTENT_SECURITY_POLICY,
)
app.config.setdefault(
    "PERMISSIONS_POLICY",
    os.environ.get("FIDO_SERVER_PERMISSIONS_POLICY") or _DEFAULT_PERMISSIONS_POLICY,
)
app.config.setdefault(
    "STRICT_TRANSPORT_SECURITY",
    os.environ.get("FIDO_SERVER_STRICT_TRANSPORT_SECURITY")
    or _DEFAULT_STRICT_TRANSPORT_SECURITY,
)


def set_security_headers(response):
    """Attach the baseline security headers to every response."""

    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    # Belt and braces with frame-ancestors for pre-CSP2 browsers.
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")

    policy = app.config.get("CONTENT_SECURITY_POLICY")
    if policy:
        headers.setdefault("Content-Security-Policy", policy)

    permissions_policy = app.config.get("PERMISSIONS_POLICY")
    if permissions_policy:
        headers.setdefault("Permissions-Policy", permissions_policy)

    # HSTS is meaningless on a plain-HTTP response and actively harmful in a
    # local http:// workflow, so it is emitted only for requests that actually
    # arrived over TLS (which needs ProxyFix behind Cloud Run, see above).
    hsts = app.config.get("STRICT_TRANSPORT_SECURITY")
    if hsts and has_request_context() and request.is_secure:
        headers.setdefault("Strict-Transport-Security", hsts)

    return response


setattr(set_security_headers, _SECURITY_HEADERS_MARKER, True)


def _register_security_headers_once(flask_app: Flask, handler) -> None:
    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, _SECURITY_HEADERS_MARKER, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)


_register_security_headers_once(app, set_security_headers)
