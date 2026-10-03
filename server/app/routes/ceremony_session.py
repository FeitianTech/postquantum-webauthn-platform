"""The session as each ceremony's begin leaves it.

A begin keeps its ceremony's state in the signed session cookie, and its complete
reads it back. A browser drops a cookie past about 4 KB and keeps the one it had,
so a begin whose session would not fit is refused, and the session left as it was.
"""
from __future__ import annotations

import copy
import functools
import logging
from collections.abc import Callable
from typing import Any

from flask import current_app, jsonify, session

from ..config import session_cookie

logger = logging.getLogger(__name__)

TOO_LARGE = (
    "This request is too large to keep until the ceremony completes: its session cookie "
    "would pass the browser's 4 KB limit. Please shorten it and try again."
)


def ceremony_begin(view: Callable[..., Any]) -> Callable[..., Any]:
    """Refuse the begin, keeping the session as it was, when its cookie would not fit."""

    @functools.wraps(view)
    def begin(*args: Any, **kwargs: Any) -> Any:
        before = copy.deepcopy(dict(session))
        response = current_app.make_response(view(*args, **kwargs))
        size = session_cookie.cookie_size(current_app, session)
        if size <= current_app.config["MAX_COOKIE_SIZE"]:
            return response
        session.clear()
        session.update(before)
        logger.warning("Refused %s: its session cookie would take %d bytes", view.__name__, size)
        if response.status_code >= 400:
            return response
        return jsonify({"error": TOO_LARGE}), 400

    return begin
