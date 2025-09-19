"""Application entry point for the WebAuthn demo server."""
from __future__ import annotations

import pathlib
import sys

if __package__:
    from .config import app
    from .routes import advanced  # noqa: F401
    from .routes import general  # noqa: F401
    from .routes import simple  # noqa: F401
else:  # pragma: no cover - executed when run as a script.
    _PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent
    _PROJECT_ROOT = _PACKAGE_ROOT.parent
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))

    from server.config import app
    from server.routes import advanced  # noqa: F401
    from server.routes import general  # noqa: F401
    from server.routes import simple  # noqa: F401


def main() -> None:
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host="localhost",
        port=5000,
        ssl_context=("localhost+1.pem", "localhost+1-key.pem"),
        debug=True,
    )


__all__ = ["app", "main"]


if __name__ == "__main__":  # pragma: no cover - convenience script entry point.
    main()
