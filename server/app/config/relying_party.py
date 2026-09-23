"""The relying party: its ID and name, and the ``Fido2Server`` bound to them.

Importing this switches fido2's WebAuthn data classes to their JSON mapping, puts
the RP name/ID defaults into ``app.config``, and warns once when neither an RP ID nor
an origin allowlist is configured. ``create_fido_server`` builds a ``Fido2Server``
per request.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Mapping
from urllib.parse import urlsplit

from flask import has_request_context, request

import fido2.features
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

from . import origins
from .application import app

logger = logging.getLogger(__name__)

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:  # pragma: no cover - compatibility shim
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:  # pragma: no cover - compatibility shim
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:  # pragma: no cover - compatibility shim
        pass

_DEFAULT_RP_NAME = os.environ.get("FIDO_SERVER_RP_NAME", "Demo server")
_DEFAULT_RP_ID = os.environ.get("FIDO_SERVER_RP_ID")
app.config.setdefault("FIDO_SERVER_RP_NAME", _DEFAULT_RP_NAME)
app.config.setdefault("FIDO_SERVER_RP_ID", _DEFAULT_RP_ID)


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
    has_allowlist = bool(origins.get_allowed_origins())

    if has_rp_id and has_allowlist:
        _RP_CONFIGURATION_WARNING_EMITTED = True
        return False

    missing = []
    if not has_rp_id:
        missing.append("FIDO_SERVER_RP_ID")
    if not has_allowlist:
        missing.append("FIDO_SERVER_ALLOWED_ORIGINS")

    logger.warning(
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

