"""Where the server's files are: the project root, runtime data and the instance folder.

``basepath`` is the ``server.app`` package directory.
"""
from __future__ import annotations

import os
from pathlib import Path

# server/app, the package this config package lives in.
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]


# server/app -> the checkout, or /app in the image (which copies server/app to
# /app/server/app).
_PROJECT_ROOT = _PACKAGE_ROOT.parents[1]
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
