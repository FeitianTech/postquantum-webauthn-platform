"""Session identifier, cookie, and directory helpers."""
from __future__ import annotations


def _normalise_session_identifier(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


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

    g._session_metadata_cookie = normalised

    @after_this_request
    def _apply_cookie(response):
        response.set_cookie(
            _SESSION_METADATA_COOKIE_NAME,
            normalised,
            max_age=_SESSION_METADATA_COOKIE_MAX_AGE,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path=cookie_path,
        )
        return response


def _get_metadata_session_id(*, create: bool = False) -> Optional[str]:
    if not has_request_context():
        return None

    cookie_identifier = _normalise_session_identifier(
        request.cookies.get(_SESSION_METADATA_COOKIE_NAME)
    )
    if cookie_identifier:
        session[_SESSION_METADATA_SESSION_KEY] = cookie_identifier
        _schedule_session_cookie(cookie_identifier)
        return cookie_identifier

    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str):
        identifier = _normalise_session_identifier(existing)
        if identifier:
            session[_SESSION_METADATA_SESSION_KEY] = identifier
            _schedule_session_cookie(identifier)
            return identifier

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
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
) -> Optional[str]:
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
        _schedule_inactive_session_cleanup()
    return normalised


def _note_session_activity(session_id: str, *, directory: Optional[str] = None) -> None:
    normalised = _normalise_session_identifier(session_id)
    if not normalised:
        return

    _touch_session_last_access(normalised)
    _schedule_inactive_session_cleanup()


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
