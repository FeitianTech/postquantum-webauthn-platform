"""Application entry point for the WebAuthn demo server."""
from __future__ import annotations

import importlib
import os
import pathlib
import sys
from types import ModuleType

_PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_ROOT.parent


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
    _import_base = _PACKAGE_ROOT.name
    __package__ = _import_base

config_module = _import_module(f"{_import_base}.config")
app = config_module.app

# Import the route modules so their decorators register endpoints with Flask.
advanced = _import_module(f"{_import_base}.routes.advanced")  # noqa: F401
general = _import_module(f"{_import_base}.routes.general")  # noqa: F401
simple = _import_module(f"{_import_base}.routes.simple")  # noqa: F401


def main() -> None:
    ensure_metadata = getattr(general, "ensure_metadata_bootstrapped", None)
    if callable(ensure_metadata):
        ensure_metadata(skip_if_reloader_parent=False)

    host = os.environ.get("WEBAUTHN_DEMO_SERVER_HOST", config_module.rp.id or "localhost")
    port = int(os.environ.get("WEBAUTHN_DEMO_SERVER_PORT", "5000"))

    config_module.configure_relying_party(host)

    ssl_cert = os.environ.get("WEBAUTHN_DEMO_SERVER_CERT", "localhost+1.pem")
    ssl_key = os.environ.get("WEBAUTHN_DEMO_SERVER_KEY", "localhost+1-key.pem")

    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host=host,
        port=port,
        ssl_context=(ssl_cert, ssl_key),
        debug=True,
    )


__all__ = ["app", "main"]


if __name__ == "__main__":  # pragma: no cover - convenience script entry point.
    main()
