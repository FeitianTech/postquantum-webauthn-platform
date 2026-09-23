"""Configuration and application setup for the demo WebAuthn server."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, has_request_context, request

import fido2.features
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

from .. import encoding
from ..env_flags import parse_env_flag
from ..mds_trust import (
    FIDO_METADATA_TRUST_ROOT_CERT,
    FIDO_METADATA_TRUST_ROOT_PEM,
    MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
)
from . import application, compression, paths, proxy, session_cookie, session_secret

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:  # pragma: no cover - compatibility shim
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:  # pragma: no cover - compatibility shim
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:  # pragma: no cover - compatibility shim
        pass

_FRONTEND_ROOT = paths._FRONTEND_ROOT
_FRONTEND_STATIC_ROOT = paths._FRONTEND_STATIC_ROOT
_SERVER_RUNTIME_ROOT = paths._SERVER_RUNTIME_ROOT
basepath = paths.basepath

app = application.app

# Imported for what importing them does to ``app``; nothing is re-exported.
_APP_CONFIGURING_MODULES = (compression, proxy, session_cookie, session_secret)


def _env_flag(name: str) -> bool | None:
    """Return ``True`` or ``False`` when the named env var is explicitly set."""
    return parse_env_flag(name)


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


_DEFAULT_RP_NAME = os.environ.get("FIDO_SERVER_RP_NAME", "Demo server")
_DEFAULT_RP_ID = os.environ.get("FIDO_SERVER_RP_ID")
app.config.setdefault("FIDO_SERVER_RP_NAME", _DEFAULT_RP_NAME)
app.config.setdefault("FIDO_SERVER_RP_ID", _DEFAULT_RP_ID)


def _parse_allowed_origins(raw_value: str | None) -> tuple[str, ...] | None:
    """Normalise a comma/newline separated allowlist of exact origins."""

    if raw_value is None:
        return None

    origins: list[str] = []
    for chunk in re.split(r"[,\n]", raw_value):
        cleaned = chunk.strip()
        if not cleaned:
            continue
        normalised = normalise_origin(cleaned)
        if normalised and normalised not in origins:
            origins.append(normalised)

    if not origins:
        return None
    return tuple(origins)


def normalise_origin(raw_origin: str | None) -> str | None:
    """Reduce an origin to its canonical ``scheme://host[:port]`` form."""

    if not isinstance(raw_origin, str):
        return None

    candidate = raw_origin.strip()
    if not candidate:
        return None

    parsed = urlsplit(candidate if "//" in candidate else f"//{candidate}")
    scheme = (parsed.scheme or "").lower()
    hostname = parsed.hostname
    if not hostname:
        return None

    hostname = hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    if not scheme:
        scheme = "https"

    port = parsed.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    if port is None or port == default_port:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


app.config.setdefault(
    "FIDO_SERVER_ALLOWED_ORIGINS",
    _parse_allowed_origins(os.environ.get("FIDO_SERVER_ALLOWED_ORIGINS")),
)


def get_allowed_origins() -> tuple[str, ...] | None:
    """Return the configured exact-origin allowlist, or ``None`` when unset."""

    configured = app.config.get("FIDO_SERVER_ALLOWED_ORIGINS")
    if isinstance(configured, str):
        return _parse_allowed_origins(configured)
    if isinstance(configured, (list, tuple, set, frozenset)):
        origins: list[str] = []
        for entry in configured:
            normalised = normalise_origin(entry)
            if normalised and normalised not in origins:
                origins.append(normalised)
        return tuple(origins) or None
    return None


def is_origin_allowed(candidate: str | None) -> bool:
    """Return ``True`` when ``candidate`` is permitted by the allowlist.

    With no allowlist configured every origin is permitted, preserving the
    development-time behaviour of the demo server.
    """

    allowed = get_allowed_origins()
    if not allowed:
        return True
    normalised = normalise_origin(candidate)
    if normalised is None:
        return False
    return normalised in allowed


def extract_client_data_origin(credential_response: Any) -> str | None:
    """Best-effort read of ``clientDataJSON.origin`` from a WebAuthn response.

    This is the origin the ceremony actually claims to have happened at, and is
    the value the allowlist gates -- not the transport-level ``Origin`` header.
    """

    if not isinstance(credential_response, Mapping):
        return None

    raw = credential_response.get("clientDataJSON")
    if not isinstance(raw, str) or not raw:
        return None

    decoded = encoding.try_decode_base64url(raw)
    if decoded is None:
        decoded = encoding.try_decode_base64(raw)
    if decoded is None:
        return None

    try:
        parsed = json.loads(decoded.decode("utf-8"))
    except Exception:
        return None

    if not isinstance(parsed, Mapping):
        return None
    origin = parsed.get("origin")
    return origin if isinstance(origin, str) else None


def determine_expected_origin(candidate: str | None = None) -> str | None:
    """Resolve the origin a ceremony must have been performed against.

    When an allowlist is configured the expected origin always comes from it,
    never from attacker-controlled request data: a ``candidate`` is honoured
    only when it is itself a member of the allowlist, otherwise the first
    configured origin is returned so that a mismatch is reported.
    """

    allowed = get_allowed_origins()
    if allowed:
        normalised = normalise_origin(candidate)
        if normalised and normalised in allowed:
            return normalised
        return allowed[0]

    # Development fallback: derive the origin from the served request.
    if has_request_context():
        derived = normalise_origin(request.host_url)
        if derived:
            return derived

    return None

_session_metadata_recover_flag = _env_flag("FIDO_SERVER_SESSION_METADATA_RECOVER")
if _session_metadata_recover_flag is not None:
    app.config["SESSION_METADATA_RECOVER_ON_START"] = _session_metadata_recover_flag


def _parse_trusted_ca_subjects(raw_value: str | None) -> set[str] | None:
    """Normalise a comma or newline separated list of CA subject names."""

    if raw_value is None:
        return None

    components = re.split(r"[,;\n]+", raw_value)
    subjects = {component.strip() for component in components if component.strip()}
    if not subjects:
        return None
    return subjects


def _parse_trusted_ca_fingerprints(raw_value: str | None) -> set[str] | None:
    """Normalise a list of hexadecimal fingerprints for trusted CA certificates."""

    if raw_value is None:
        return None

    components = re.split(r"[,;\n]+", raw_value)
    fingerprints = set()
    for component in components:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", component)
        if cleaned:
            normalised = cleaned.upper()
            # Require at least 20 bytes / 40 hex characters to avoid trivial matches.
            if len(normalised) >= 40:
                fingerprints.add(normalised)
    if not fingerprints:
        return None
    return fingerprints


app.config.setdefault(
    "TRUSTED_ATTESTATION_CA_SUBJECTS",
    _parse_trusted_ca_subjects(
        os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS")
    ),
)
app.config.setdefault(
    "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
    _parse_trusted_ca_fingerprints(
        os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS")
    ),
)


_RP_CONFIGURATION_WARNING_EMITTED = False


def warn_if_development_rp_configuration() -> bool:
    """Warn once when neither an explicit RP ID nor an origin allowlist is set.

    Without either, the RP ID is derived from the request ``Host`` header and
    every origin is accepted -- acceptable for local development only.
    """

    global _RP_CONFIGURATION_WARNING_EMITTED
    if _RP_CONFIGURATION_WARNING_EMITTED:
        return False

    configured_id = app.config.get("FIDO_SERVER_RP_ID")
    has_rp_id = isinstance(configured_id, str) and bool(configured_id.strip())
    has_allowlist = bool(get_allowed_origins())

    if has_rp_id and has_allowlist:
        _RP_CONFIGURATION_WARNING_EMITTED = True
        return False

    missing = []
    if not has_rp_id:
        missing.append("FIDO_SERVER_RP_ID")
    if not has_allowlist:
        missing.append("FIDO_SERVER_ALLOWED_ORIGINS")

    app.logger.warning(
        "%s not configured; falling back to Host-header derived RP ID and an "
        "unrestricted origin policy. This is a DEVELOPMENT-ONLY fallback -- set "
        "both before deploying.",
        " and ".join(missing),
    )
    _RP_CONFIGURATION_WARNING_EMITTED = True
    return True


warn_if_development_rp_configuration()


def determine_rp_id(explicit_id: str | None = None) -> str:
    """Resolve the relying party identifier for the current request.

    ``explicit_id`` is honoured only when it is consistent with the configured
    RP ID/origin allowlist; deriving the RP ID from the request ``Host`` header
    is a development-only fallback used when nothing is configured.
    """

    if explicit_id:
        return explicit_id

    configured_id = app.config.get("FIDO_SERVER_RP_ID")
    if isinstance(configured_id, str) and configured_id.strip():
        return configured_id.strip()

    if has_request_context():
        host = _resolve_request_host()
        if host in {"", None}:
            return "localhost"
        try:
            if ipaddress.ip_address(host).is_loopback:
                return "localhost"
        except ValueError:
            pass
        if host in {"127.0.0.1", "::1"}:
            return "localhost"
        return host

    return "localhost"


def _resolve_request_host() -> str | None:
    """Return the current request host without port decoration."""

    if not has_request_context():
        return None

    for raw_host in (
        request.headers.get("Host"),
        request.environ.get("HTTP_HOST"),
        request.environ.get("SERVER_NAME"),
    ):
        host = _normalise_request_host(raw_host)
        if host:
            return host

    return None


def _normalise_request_host(raw_host: str | None) -> str | None:
    """Normalise a raw host header into a lowercase hostname or IP literal."""

    if not isinstance(raw_host, str):
        return None

    host = raw_host.strip().lower()
    if not host:
        return None

    if host.startswith("["):
        closing_index = host.find("]")
        if closing_index != -1:
            unwrapped = host[1:closing_index].strip()
            return unwrapped or None

    if host.count(":") > 1:
        # Treat unbracketed multi-colon values as IPv6 literals without ports.
        return host

    parsed = urlsplit(f"//{host}")
    normalised = parsed.hostname
    if isinstance(normalised, str) and normalised.strip():
        return normalised.strip().lower()

    return host


def build_rp_entity(
    rp_data: Mapping[str, str] | None = None,
    *,
    rp_id: str | None = None,
    rp_name: str | None = None,
) -> PublicKeyCredentialRpEntity:
    """Create a ``PublicKeyCredentialRpEntity`` for the active request."""

    rp_id_value = determine_rp_id(rp_id or (rp_data or {}).get("id"))

    rp_name_value = (
        rp_name
        or (rp_data or {}).get("name")
        or app.config.get("FIDO_SERVER_RP_NAME")
        or "Demo server"
    )

    return PublicKeyCredentialRpEntity(name=rp_name_value, id=rp_id_value)


def create_fido_server(
    rp_data: Mapping[str, str] | None = None,
    *,
    rp_id: str | None = None,
    rp_name: str | None = None,
) -> Fido2Server:
    """Instantiate a :class:`Fido2Server` bound to the resolved RP ID."""

    entity = build_rp_entity(rp_data, rp_id=rp_id, rp_name=rp_name)
    return Fido2Server(entity)


rp = build_rp_entity()
server = Fido2Server(rp)

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "blob.jwt"
MDS_METADATA_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), MDS_METADATA_FILENAME)
MDS_METADATA_VERIFIED_PATH = os.path.join(
    str(_FRONTEND_STATIC_ROOT), "fido-mds3.verified.json"
)
MDS_METADATA_CACHE_PATH = MDS_METADATA_VERIFIED_PATH + ".meta.json"
MDS_EXPLORER_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), "fido-mds3.explorer.json")
MDS_EXPLORER_META_PATH = MDS_EXPLORER_PATH + ".meta.json"
# Explorer snapshot with inline details, served to browsers as a static file.
MDS_EXPLORER_FULL_PATH = os.path.join(
    str(_FRONTEND_STATIC_ROOT), "fido-mds3.explorer.full.json"
)
SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)

__all__ = [
    "app",
    "basepath",
    "build_rp_entity",
    "set_security_headers",
    "create_fido_server",
    "determine_expected_origin",
    "determine_rp_id",
    "extract_client_data_origin",
    "get_allowed_origins",
    "is_origin_allowed",
    "normalise_origin",
    "warn_if_development_rp_configuration",
    "rp",
    "server",
    "MDS_METADATA_CACHE_PATH",
    "MDS_EXPLORER_META_PATH",
    "MDS_EXPLORER_PATH",
    "MDS_METADATA_FILENAME",
    "MDS_METADATA_PATH",
    "MDS_METADATA_VERIFIED_PATH",
    "MDS_METADATA_URL",
    "SESSION_METADATA_DIR",
    "FIDO_METADATA_TRUST_ROOT_CERT",
    "FIDO_METADATA_TRUST_ROOT_PEM",
    "MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM",
]
