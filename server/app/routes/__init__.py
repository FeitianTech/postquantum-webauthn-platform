"""Route registrations for the WebAuthn demo server."""

# Each module defines a Blueprint, ``bp``, that the app registers.
from . import (
    advanced,
    general,
    simple,
)

__all__ = ["advanced", "general", "simple"]
