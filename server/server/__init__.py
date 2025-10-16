"""Server package exposing the Flask application."""
from __future__ import annotations

from importlib import import_module
from typing import Any, TYPE_CHECKING

__all__ = ["app", "main"]


if TYPE_CHECKING:  # pragma: no cover - import only for static analysis.
    from .app import app as _app  # noqa: F401
    from .app import main as _main  # noqa: F401

    app = _app
    main = _main


def __getattr__(name: str) -> Any:
    """Lazily import attributes exposed at the package level.

    Importing ``server.server`` from modules that also depend on
    ``updater.mds_updater`` created a circular import because the previous
    implementation imported ``.app`` eagerly. The ``.app`` module in turn
    imports the Flask route modules, which import the updater module while it
    is still initialising. By delaying the import until the attribute is
    requested we avoid loading the routes during module initialisation, which
    breaks the cycle while retaining the existing public API.
    """

    if name in __all__:
        module = import_module(".app", __name__)
        return getattr(module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Ensure ``dir(server.server)`` exposes lazily imported names."""

    return sorted(set(globals()) | set(__all__))
