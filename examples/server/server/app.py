"""Application entry point for the WebAuthn demo server."""
from __future__ import annotations

from .config import app
from .routes import advanced  # noqa: F401
from .routes import general  # noqa: F401
from .routes import simple  # noqa: F401


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
