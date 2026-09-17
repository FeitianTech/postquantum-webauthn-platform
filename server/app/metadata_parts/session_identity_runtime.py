"""Session identifier, cookie, and directory helpers."""
from __future__ import annotations

import os
import secrets
import time
from typing import Any

from flask import after_this_request, g, has_request_context, request, session

from .. import session_metadata_store
from ..config import app
from . import session_cleanup_runtime
from .runtime_state import (
    _SESSION_METADATA_COOKIE_MAX_AGE,
    _SESSION_METADATA_COOKIE_NAME,
    _SESSION_METADATA_SESSION_KEY,
    _SESSION_METADATA_SUFFIX,
    _SESSION_METADATA_TOUCH_KEY,
    _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS,
    _SESSION_METADATA_TOUCH_THROTTLE_ENV,
)


def _normalise_session_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


# NOTE: every function in this module is rebound onto ``server.app.metadata``'s
# globals by ``_install_runtime_bindings``, so only names that exist there are
# resolvable at call time.  That is why the cookie signing below is written
# inline (with a literal salt) instead of being factored into helpers here.
#
# Salt for the metadata-session recovery cookie; the key is ``app.secret_key``.


def _schedule_session_cookie(identifier: str) -> None:
    if not has_request_context():
        return

    normalised = _normalise_session_identifier(identifier)
    if not normalised:
        return

    _note_session_activity(normalised)

    secure = bool(request.is_secure)
    cookie_path = "/"
    samesite = "None" if secure else "Lax"

    if getattr(g, "_session_metadata_cookie", None) == normalised:
        return

    # The recovery cookie is client storage.  Handing back a bare namespace name
    # lets anyone who can set a cookie point themselves at another visitor's
    # namespace, so the value that leaves the server is signed with the
    # application secret and the signature is re-checked on the way back in.
    secret = app.secret_key
    if not secret:
        return

    from itsdangerous import URLSafeTimedSerializer

    sealed = URLSafeTimedSerializer(
        secret, salt="fido.mds.session-cookie.v1"
    ).dumps(normalised)

    g._session_metadata_cookie = normalised

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            _SESSION_METADATA_COOKIE_NAME,
            sealed,
            max_age=_SESSION_METADATA_COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path=cookie_path,
        )
        return response


def _get_metadata_session_id(*, create: bool = False) -> str | None:
    if not has_request_context():
        return None

    # The signed Flask session is authoritative.  It is authenticated with the
    # application secret, so a caller cannot point it at somebody else's
    # namespace.
    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str):
        identifier = _normalise_session_identifier(existing)
        if identifier:
            session[_SESSION_METADATA_SESSION_KEY] = identifier
            _schedule_session_cookie(identifier)
            return identifier

    # Otherwise fall back to the long-lived recovery cookie, so a returning
    # visitor keeps their namespace after the (much shorter lived) Flask session
    # has expired.  Only a cookie this server signed is honoured; a forged or
    # replayed-from-elsewhere value is ignored and a fresh namespace is minted
    # instead, which is what stops one caller reading another's stored metadata
    # and credential artifacts.
    cookie_identifier = None
    raw_cookie = request.cookies.get(_SESSION_METADATA_COOKIE_NAME)
    secret = app.secret_key
    if isinstance(raw_cookie, str) and raw_cookie and secret:
        from itsdangerous import BadSignature, URLSafeTimedSerializer

        try:
            unsealed = URLSafeTimedSerializer(
                secret, salt="fido.mds.session-cookie.v1"
            ).loads(raw_cookie, max_age=_SESSION_METADATA_COOKIE_MAX_AGE)
        except BadSignature:
            # Also covers SignatureExpired / BadTimeSignature.
            unsealed = None
        except Exception:
            unsealed = None
        cookie_identifier = _normalise_session_identifier(unsealed)

    if cookie_identifier:
        session[_SESSION_METADATA_SESSION_KEY] = cookie_identifier
        _schedule_session_cookie(cookie_identifier)
        return cookie_identifier

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
    # A brand-new session has nothing stored yet, so it does not need a
    # last-access marker until it writes data (writes refresh it themselves).
    g._mds_session_new = identifier
    _schedule_session_cookie(identifier)
    return identifier


def ensure_metadata_session_id() -> str:
    identifier = _get_metadata_session_id(create=True)
    if not identifier:
        raise RuntimeError("Unable to establish metadata session identifier.")
    if has_request_context():
        session.permanent = True
    return identifier


def _session_metadata_directory(
    session_id: str, *, create: bool = False, cleanup: bool = True
) -> str | None:
    if not session_id:
        return None

    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return None

    if create:
        try:
            session_metadata_store.ensure_session(normalised)
        except Exception as exc:
            app.logger.error(
                "Failed to prepare session metadata storage for %s: %s", normalised, exc
            )
            raise
    if cleanup:
        session_cleanup_runtime._schedule_inactive_session_cleanup()
    return normalised


def _note_session_activity(session_id: str, *, directory: str | None = None) -> None:
    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return

    if has_request_context():
        # Refreshing the marker is a storage write, so do it at most once per
        # request and at most once per throttle window per session.
        if getattr(g, "_mds_session_touched", None) == normalised:
            return
        g._mds_session_touched = normalised

        now = time.time()
        if getattr(g, "_mds_session_new", None) == normalised:
            session[_SESSION_METADATA_TOUCH_KEY] = now
            session_cleanup_runtime._schedule_inactive_session_cleanup()
            return

        raw_throttle = os.environ.get(_SESSION_METADATA_TOUCH_THROTTLE_ENV)
        try:
            throttle = (
                float(raw_throttle)
                if raw_throttle
                else _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS
            )
        except ValueError:
            throttle = _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS

        last_touch = session.get(_SESSION_METADATA_TOUCH_KEY)
        if isinstance(last_touch, (int, float)) and 0 <= now - last_touch < throttle:
            session_cleanup_runtime._schedule_inactive_session_cleanup()
            return
        session[_SESSION_METADATA_TOUCH_KEY] = now

    session_cleanup_runtime._touch_session_last_access(normalised)
    session_cleanup_runtime._schedule_inactive_session_cleanup()


def _validate_session_metadata_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise ValueError("Invalid metadata filename.")

    trimmed = filename.strip()
    if not trimmed:
        raise ValueError("Invalid metadata filename.")

    if trimmed.startswith("."):
        raise ValueError("Invalid metadata filename.")

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            raise ValueError("Invalid metadata filename.")

    if os.path.basename(trimmed) != trimmed:
        raise ValueError("Invalid metadata filename.")

    if not trimmed.endswith(_SESSION_METADATA_SUFFIX):
        raise ValueError("Invalid metadata filename.")

    return trimmed
