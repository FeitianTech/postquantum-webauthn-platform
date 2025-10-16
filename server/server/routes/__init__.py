"""Route registrations for the WebAuthn demo server."""

# Import submodules to register routes via decorators.
from . import advanced  # noqa: F401
from . import general  # noqa: F401
from . import simple  # noqa: F401

__all__ = ["advanced", "general", "simple"]
