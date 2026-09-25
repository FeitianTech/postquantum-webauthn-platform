"""Response security headers: CSP, Permissions-Policy, HSTS and friends.

``create_app()`` puts the defaults into ``app.config`` and registers the handler
with ``init_app``. Flask runs ``after_request`` handlers in reverse, so this one,
registered after ``compression``'s, runs before it.
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, current_app, has_request_context, request

_SECURITY_HEADERS_MARKER = "_postquantum_security_headers"

# Violation reports go to routes/csp_report.py, which logs each in one line:
# report-uri for Firefox and Safari, report-to (the "csp" endpoint of
# Reporting-Endpoints) for Chromium, which then ignores report-uri.
_REPORT_ENDPOINT = "/api/csp-report"
_REPORT_GROUP = "csp"
_REPORTING = (f"report-uri {_REPORT_ENDPOINT}", f"report-to {_REPORT_GROUP}")

# Strict: no 'unsafe-inline' for scripts or styles. The templates hold no inline
# handler, script or style attribute (tests/app/tooling/test_inline_code.py keeps
# it so): controls name their action with data-action, the page's data is a
# <script type="application/json"> block, and scripts style through CSSOM
# (element.style), which style-src does not govern.
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
        # The Google Fonts stylesheet linked from index.html.
        "style-src 'self' https://fonts.googleapis.com",
        "script-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
        *_REPORTING,
    )
)

# Trusted Types, report-only: every string given to a sink that parses HTML or
# loads script (innerHTML, document.write, ...) is reported, and nothing is
# blocked. No script gives one a string (tests/app/tooling/test_html_sinks.py);
# enforcing it waits for the final audit, once production reports none.
_DEFAULT_CONTENT_SECURITY_POLICY_REPORT_ONLY = "; ".join(
    ("require-trusted-types-for 'script'", *_REPORTING)
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
        "CONTENT_SECURITY_POLICY_REPORT_ONLY": os.environ.get("FIDO_SERVER_CONTENT_SECURITY_POLICY_REPORT_ONLY")
        or _DEFAULT_CONTENT_SECURITY_POLICY_REPORT_ONLY,
        "REPORTING_ENDPOINTS": os.environ.get("FIDO_SERVER_REPORTING_ENDPOINTS")
        or _DEFAULT_REPORTING_ENDPOINTS,
        "PERMISSIONS_POLICY": os.environ.get("FIDO_SERVER_PERMISSIONS_POLICY")
        or _DEFAULT_PERMISSIONS_POLICY,
        "STRICT_TRANSPORT_SECURITY": os.environ.get("FIDO_SERVER_STRICT_TRANSPORT_SECURITY")
        or _DEFAULT_STRICT_TRANSPORT_SECURITY,
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

    report_only_policy = current_app.config.get("CONTENT_SECURITY_POLICY_REPORT_ONLY")
    if report_only_policy:
        headers.setdefault("Content-Security-Policy-Report-Only", report_only_policy)

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


def _register_security_headers_once(flask_app: Flask, handler) -> None:
    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, _SECURITY_HEADERS_MARKER, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)


def init_app(app: Flask) -> None:
    """Register ``set_security_headers`` as an ``after_request`` handler."""

    _register_security_headers_once(app, set_security_headers)
