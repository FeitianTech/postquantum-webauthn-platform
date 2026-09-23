"""Application entry point for the WebAuthn demo server."""
from __future__ import annotations

from . import static_assets
from .config import app
from .routes import advanced, general, simple

static_assets.init_app(app)
for _blueprint in (advanced.bp, general.bp, simple.bp):
    app.register_blueprint(_blueprint)


def main() -> None:
    ensure_metadata = getattr(general, "ensure_metadata_bootstrapped", None)
    if callable(ensure_metadata):
        ensure_metadata(skip_if_reloader_parent=False)

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
