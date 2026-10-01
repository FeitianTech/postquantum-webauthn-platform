"""The application the entry point builds (``server.app.app:app``).

Read from the module each time it is asked for, so a test that patches the
module's ``app`` is the only one that sees its stand-in.
"""

from __future__ import annotations

from typing import Any

from server.app import app as app_module


def entry_app() -> Any:
    return app_module.app
