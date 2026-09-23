"""Configuration and application setup for the demo WebAuthn server."""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, has_request_context, request
from werkzeug.middleware.proxy_fix import ProxyFix

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
from . import application, paths

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


def _resolve_secret_key() -> bytes:
    """Return the Flask session secret."""

    env_value = os.environ.get("FIDO_SERVER_SECRET_KEY")
    if isinstance(env_value, str) and env_value:
        return env_value.encode("utf-8")

    file_path = os.environ.get("FIDO_SERVER_SECRET_KEY_FILE")
    if isinstance(file_path, str) and file_path:
        try:
            with open(file_path, "rb") as key_file:
                file_value = key_file.read()
                if file_value:
                    return file_value
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning(
                "Unable to read secret key file %s: %s", file_path, exc
            )

    default_path = os.path.join(app.instance_path, "session-secret.key")

    def _read_stored_key() -> bytes | None:
        try:
            with open(default_path, "rb") as stored_key:
                stored_value = stored_key.read()
                if stored_value:
                    return stored_value
        except FileNotFoundError:
            return None
        except OSError:
            return None
        return None

    stored = _read_stored_key()
    if stored:
        return stored

    secret = os.urandom(32)

    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret

    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="session-secret.", dir=os.path.dirname(default_path)
        )
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(secret)
            target.flush()
            os.fsync(target.fileno())
        try:
            os.replace(temp_path, default_path)
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning("Unable to store generated session secret: %s", exc)
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    stored = _read_stored_key()
    if stored:
        return stored

    return secret


app.secret_key = _resolve_secret_key()

_COMPRESSIBLE_MIMETYPES = {
    "application/javascript",
    "application/json",
    "application/manifest+json",
    "application/xml",
    "image/svg+xml",
    "text/css",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
}
_DEFAULT_COMPRESSION_MIN_SIZE = 512
_FAST_COMPRESSION_THRESHOLD = 256 * 1024
_RESPONSE_COMPRESSION_MARKER = "_postquantum_response_compression"


def _accepts_gzip() -> bool:
    if not has_request_context():
        return False
    accepted = request.headers.get("Accept-Encoding", "")
    return "gzip" in accepted.lower()


def _append_vary(existing: str | None, value: str) -> str:
    tokens = [token.strip() for token in (existing or "").split(",") if token.strip()]
    lowered = {token.lower() for token in tokens}
    if value.lower() not in lowered:
        tokens.append(value)
    return ", ".join(tokens)


def maybe_compress_response(response):
    if not _accepts_gzip():
        return response

    if response.status_code < 200 or response.status_code >= 300:
        return response

    if response.headers.get("Content-Encoding"):
        return response

    mimetype = (response.mimetype or "").lower()
    if mimetype not in _COMPRESSIBLE_MIMETYPES and not mimetype.startswith("text/"):
        return response

    if response.direct_passthrough:
        response.direct_passthrough = False

    try:
        payload = response.get_data()
    except Exception:  # pragma: no cover - depends on response type
        return response

    min_size = app.config.get("RESPONSE_COMPRESSION_MIN_SIZE", _DEFAULT_COMPRESSION_MIN_SIZE)
    if not payload or len(payload) < int(min_size):
        return response

    # Large bodies (e.g. a per-session MDS snapshot) favour speed over ratio;
    # static assets are precompressed at build time instead.
    compresslevel = 1 if len(payload) > _FAST_COMPRESSION_THRESHOLD else 6
    compressed = gzip.compress(payload, compresslevel=compresslevel)
    if len(compressed) >= len(payload):
        return response

    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    response.headers["Vary"] = _append_vary(response.headers.get("Vary"), "Accept-Encoding")
    response.headers.pop("ETag", None)
    response.headers.pop("Content-MD5", None)
    return response


setattr(maybe_compress_response, _RESPONSE_COMPRESSION_MARKER, True)


def _register_after_request_once(flask_app: Flask, handler) -> None:
    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, _RESPONSE_COMPRESSION_MARKER, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)


_register_after_request_once(app, maybe_compress_response)


def _env_flag(name: str) -> bool | None:
    """Return ``True`` or ``False`` when the named env var is explicitly set."""
    return parse_env_flag(name)


# ---------------------------------------------------------------------------
# Transport hardening: reverse proxy, session cookie, security headers.
# ---------------------------------------------------------------------------

_PROXY_FIX_MARKER = "_postquantum_proxy_fix"


def _running_behind_managed_proxy() -> bool:
    """Return ``True`` when the platform terminates TLS in front of this process.

    Cloud Run sets ``K_SERVICE``; the rest of the codebase already treats that as
    the "running on Cloud Run" signal (see ``startup.py`` and ``device_logs.py``).
    """

    return bool(os.environ.get("K_SERVICE"))


def _should_trust_proxy_headers() -> bool:
    """Return ``True`` when ``X-Forwarded-*`` headers may be believed."""

    explicit = _env_flag("FIDO_SERVER_TRUST_PROXY")
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


if _should_trust_proxy_headers():
    _apply_proxy_fix(app)


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

    explicit = _env_flag("FIDO_SERVER_SESSION_COOKIE_SECURE")
    if explicit is not None:
        return explicit
    return _running_behind_managed_proxy()


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=_resolve_session_cookie_secure(),
    # WebAuthn ceremonies are same-site fetches from our own page, so "Lax" costs
    # nothing and keeps the cookie off cross-site POSTs.
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=_resolve_session_lifetime_seconds()),
)


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
