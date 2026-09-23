"""Where the server's files are: the project root, the frontend and runtime data.

``basepath`` is the ``server.app`` package directory, which is also where local
credential pickles are kept.
"""
from __future__ import annotations

import os
from pathlib import Path

# server/app, the package this config package lives in.
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _discover_project_root(package_root: Path) -> Path:
    """Locate the repository/application root across supported layouts."""

    for candidate in package_root.parents:
        if (candidate / "frontend").is_dir():
            return candidate

    # Fallback keeps previous behavior for environments without frontend files.
    return package_root.parents[1]


_PROJECT_ROOT = _discover_project_root(_PACKAGE_ROOT)
_FRONTEND_ROOT = _PROJECT_ROOT / "frontend"
_FRONTEND_STATIC_ROOT = _FRONTEND_ROOT / "static"
_FRONTEND_TEMPLATE_ROOT = _FRONTEND_ROOT / "templates"
_SERVER_RUNTIME_ROOT = Path(
    os.environ.get(
        "FIDO_SERVER_RUNTIME_ROOT",
        str(_PROJECT_ROOT / "server" / "runtime"),
    )
)
# Where Flask would put the instance folder for an app in the ``server`` package:
# next to ``server/``. Passed to Flask explicitly so the session secret and the
# local credential store stay where they are whatever the app is named, and so
# modules that need the path do not need the app.
INSTANCE_ROOT = str(_PACKAGE_ROOT.parents[1] / "instance")
# Save credentials next to the server.app package, regardless of CWD.
basepath = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
