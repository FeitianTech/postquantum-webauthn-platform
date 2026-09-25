"""Route registrations for the WebAuthn demo server."""

# Each module defines a Blueprint, ``bp``, that the app registers.
from . import (
    advanced,
    csp_report,
    errors,
    general,
    simple,
)

__all__ = ["advanced", "csp_report", "errors", "general", "simple"]
