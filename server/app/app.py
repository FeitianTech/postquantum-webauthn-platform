"""The WSGI entry point: ``app``, the application ``create_app()`` builds."""
from __future__ import annotations

from .factory import create_app

# The WSGI application, ``server.app.app:app``. Importing this module builds it.
app = create_app()


def main() -> None:
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host="localhost",
        port=8000,
        debug=True,
    )


__all__ = ["app", "main"]


if __name__ == "__main__":  # pragma: no cover - convenience script entry point.
    main()
