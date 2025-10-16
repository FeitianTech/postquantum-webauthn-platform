"""Server package exposing the Flask application."""
from __future__ import annotations

from .app import app, main

__all__ = ["app", "main"]
