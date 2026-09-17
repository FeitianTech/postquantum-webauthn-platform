"""Route registrations for the WebAuthn demo server."""

# Import submodules to register routes via decorators.
from . import (
    advanced,
    general,
    simple,
)

__all__ = ["advanced", "general", "simple"]
