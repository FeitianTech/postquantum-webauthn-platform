"""A visitor's namespace as tests give it and read it: the signed cookie ``visitor_session`` reads."""
from __future__ import annotations

from typing import Any

import itsdangerous

from server.app import visitor_session


def _serializer(app: Any) -> itsdangerous.URLSafeTimedSerializer:
    return itsdangerous.URLSafeTimedSerializer(app.secret_key, salt=visitor_session.COOKIE_SALT)


def sealed(app: Any, identifier: str) -> str:
    """The cookie value naming ``identifier``, signed as ``app`` signs it."""

    return _serializer(app).dumps(identifier)


def give(client: Any, identifier: str) -> None:
    """Make ``client`` a visitor whose namespace is ``identifier``."""

    client.set_cookie(visitor_session.COOKIE_NAME, sealed(client.application, identifier))


def of(client: Any) -> str | None:
    """The namespace ``client``'s cookie names, if it holds one."""

    cookie = client.get_cookie(visitor_session.COOKIE_NAME)
    return None if cookie is None else _serializer(client.application).loads(cookie.value)


def header(app: Any, identifier: str) -> dict[str, str]:
    """The request header naming ``identifier``, for ``app.test_request_context(headers=...)``."""

    return {"Cookie": f"{visitor_session.COOKIE_NAME}={sealed(app, identifier)}"}
