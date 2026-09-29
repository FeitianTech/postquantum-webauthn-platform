"""The application the entry point builds (``server.app.app:app``).

Imported when first asked for, as the entry point builds its app on import.
"""

from __future__ import annotations

from typing import Any


def entry_app() -> Any:
    from server.app.app import app

    return app
