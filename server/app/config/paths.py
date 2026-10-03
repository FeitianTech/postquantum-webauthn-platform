"""Where the server's files are: the project root and the instance folder, which
holds everything the server keeps (the session secret, the stores, the MDS snapshot).

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
# Where Flask would put the instance folder for an app in the ``server`` package:
# next to ``server/``. Passed to Flask explicitly so the session secret and the
# local credential store stay where they are whatever the app is named, and so
# modules that need the path do not need the app.
INSTANCE_ROOT = str(_PACKAGE_ROOT.parents[1] / "instance")
# The package directory, as a string: the app's root_path (config/application.py).
basepath = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def store_dir(setting: str, name: str) -> str:
    """A local store's directory: the ``setting`` environment variable when set,
    else ``instance/<name>``. Read on each call, never at import."""

    return os.environ.get(setting) or os.path.join(INSTANCE_ROOT, name)
