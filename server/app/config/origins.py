"""The exact-origin allowlist (``FIDO_SERVER_ALLOWED_ORIGINS``) and origin helpers.

``create_app()`` parses the allowlist into ``app.config``. With no allowlist every
origin is accepted, which is the development-only fallback.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from flask import current_app, has_request_context, request

from .. import encoding


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


def config_from_env() -> dict[str, Any]:
    """The allowlist setting ``create_app()`` puts into ``app.config``."""

    return {
        "FIDO_SERVER_ALLOWED_ORIGINS": _parse_allowed_origins(
            os.environ.get("FIDO_SERVER_ALLOWED_ORIGINS")
        ),
    }


def get_allowed_origins() -> tuple[str, ...] | None:
    """Return the current app's exact-origin allowlist, or ``None`` when unset."""

    return allowed_origins_from_config(current_app.config)


def allowed_origins_from_config(config: Mapping[str, Any]) -> tuple[str, ...] | None:
    """Return the exact-origin allowlist configured in ``config``, or ``None``."""

    configured = config.get("FIDO_SERVER_ALLOWED_ORIGINS")
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
