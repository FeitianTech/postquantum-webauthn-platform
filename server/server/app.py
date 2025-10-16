"""Application entry point for the WebAuthn demo server."""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys
from types import ModuleType

_PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent
_PACKAGE_PARENT = _PACKAGE_ROOT.parent


def _discover_project_root(package_root: pathlib.Path) -> pathlib.Path:
    """Locate the repository root so local imports take precedence."""

    for candidate in package_root.parents:
        if (candidate / "fido2").is_dir():
            return candidate

    # Fallback to the immediate grandparent to preserve previous behaviour.
    return package_root.parents[1]


_PROJECT_ROOT = _discover_project_root(_PACKAGE_ROOT)


def _import_module(name: str) -> ModuleType:

    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:  # pragma: no cover - environment specific.
        missing = exc.name or name
        raise ModuleNotFoundError(
            f"Unable to import '{missing}'. Ensure the demo server package "
            "and its dependencies are available on PYTHONPATH."
        ) from exc


if __package__:
    _import_base = __package__
else:  # pragma: no cover - executed when run as a script.
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))

    _import_base = f"{_PACKAGE_PARENT.name}.{_PACKAGE_ROOT.name}"

    if importlib.util.find_spec(_import_base) is None:
        if str(_PACKAGE_PARENT) not in sys.path:
            sys.path.insert(0, str(_PACKAGE_PARENT))

    __package__ = _import_base

config_module = _import_module(f"{_import_base}.config")
app = config_module.app

# Import the route modules so their decorators register endpoints with Flask.
advanced = _import_module(f"{_import_base}.routes.advanced")  # noqa: F401
general = _import_module(f"{_import_base}.routes.general")  # noqa: F401
simple = _import_module(f"{_import_base}.routes.simple")  # noqa: F401

def main() -> None:
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host="demo.ftsafe.demo",
        port=5000,
        ssl_context=("demo.ftsafe.demo.pem", "demo.ftsafe.demo-key.pem"),
        debug=True,
    )


__all__ = ["app", "main"]


if __name__ == "__main__":  # pragma: no cover - convenience script entry point.
    main()
