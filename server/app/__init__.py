"""Server package exposing the Flask application."""
from __future__ import annotations

from typing import Any

__all__ = ["app", "main"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from .app import app as flask_app, main as app_main

    resolved = {
        "app": flask_app,
        "main": app_main,
    }[name]
    globals()[name] = resolved
    return resolved
