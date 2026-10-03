"""Response security headers: CSP, Permissions-Policy, HSTS and friends.

``create_app()`` puts the defaults into ``app.config`` and registers the handler
with ``init_app``. Flask runs ``after_request`` handlers in reverse, so this one,
registered after ``compression``'s, runs before it.
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, current_app, has_request_context, request

from . import application

_SECURITY_HEADERS_MARKER = "_postquantum_security_headers"

# Violation reports go to routes/csp_report.py, which logs each in one line:
# report-uri for Firefox and Safari, report-to (the "csp" endpoint of
# Reporting-Endpoints) for Chromium, which then ignores report-uri.
_REPORT_ENDPOINT = "/api/csp-report"
_REPORT_GROUP = "csp"
_REPORTING = (f"report-uri {_REPORT_ENDPOINT}", f"report-to {_REPORT_GROUP}")

# Strict: no 'unsafe-inline' for scripts or styles, and no origin but the site's
# own. The pages are the UI's static export, which holds no inline script,
# style element or style attribute (web/scripts/check-export-csp.mjs scans every
# page); components style through CSSOM (element.style), which style-src does not
# govern, and the fonts (Geist) are self-hosted. Trusted Types are enforced: a
# string given to a sink that parses HTML or loads script (innerHTML, a script's
# src, ...) is refused unless a policy made it, and only Next's two policies may
# be made (``nextjs`` and webpack's ``nextjs#bundler``, which load its chunks).
# No script of the app gives a sink a string (tests/app/tooling/test_html_sinks.py).
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
        "font-src 'self'",
        "style-src 'self'",
        "script-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
        "require-trusted-types-for 'script'",
        "trusted-types nextjs nextjs#bundler",
        *_REPORTING,
    )
)

_DEFAULT_REPORTING_ENDPOINTS = f'{_REPORT_GROUP}="{_REPORT_ENDPOINT}"'

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



def config_from_env() -> dict[str, Any]:
    """The header policies ``create_app()`` puts into ``app.config``."""

    return {
        "CONTENT_SECURITY_POLICY": os.environ.get("FIDO_SERVER_CONTENT_SECURITY_POLICY")
        or _DEFAULT_CONTENT_SECURITY_POLICY,
        "REPORTING_ENDPOINTS": os.environ.get("FIDO_SERVER_REPORTING_ENDPOINTS")
        or _DEFAULT_REPORTING_ENDPOINTS,
        "PERMISSIONS_POLICY": _DEFAULT_PERMISSIONS_POLICY,
        "STRICT_TRANSPORT_SECURITY": _DEFAULT_STRICT_TRANSPORT_SECURITY,
    }


def set_security_headers(response):
    """Attach the baseline security headers to every response."""

    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    # Belt and braces with frame-ancestors for pre-CSP2 browsers.
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")

    policy = current_app.config.get("CONTENT_SECURITY_POLICY")
    if policy:
        headers.setdefault("Content-Security-Policy", policy)

    reporting_endpoints = current_app.config.get("REPORTING_ENDPOINTS")
    if reporting_endpoints:
        headers.setdefault("Reporting-Endpoints", reporting_endpoints)

    permissions_policy = current_app.config.get("PERMISSIONS_POLICY")
    if permissions_policy:
        headers.setdefault("Permissions-Policy", permissions_policy)

    # HSTS is meaningless on a plain-HTTP response and actively harmful in a
    # local http:// workflow, so it is emitted only for requests that actually
    # arrived over TLS (which needs ProxyFix behind Cloud Run, see above).
    hsts = current_app.config.get("STRICT_TRANSPORT_SECURITY")
    if hsts and has_request_context() and request.is_secure:
        headers.setdefault("Strict-Transport-Security", hsts)

    return response


setattr(set_security_headers, _SECURITY_HEADERS_MARKER, True)


def init_app(app: Flask) -> None:
    """Register ``set_security_headers`` as an ``after_request`` handler."""

    application.add_after_request_once(app, set_security_headers, _SECURITY_HEADERS_MARKER)
