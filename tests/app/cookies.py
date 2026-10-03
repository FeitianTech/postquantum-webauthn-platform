"""The cookies an answer sets, as tests read them."""
from __future__ import annotations

from typing import Any


def session_cookies(response: Any) -> list[str]:
    """Each Set-Cookie header of ``response`` that sets the Flask session cookie."""

    return [value for value in response.headers.getlist("Set-Cookie") if value.startswith("session=")]
