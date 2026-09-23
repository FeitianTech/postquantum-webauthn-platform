"""The Flask application singleton.

Every other config submodule configures this one object as it is imported; the
re-import guard keeps it the same object if this module is reloaded.
"""
from __future__ import annotations

from flask import Flask

from .paths import _FRONTEND_STATIC_ROOT, _FRONTEND_TEMPLATE_ROOT, basepath

_existing_app = globals().get("app")
if isinstance(_existing_app, Flask):
    app = _existing_app
else:
    # Named for the config package and rooted at server/app, exactly as when this
    # was config.py: the name is also the logger's name.
    app = Flask(
        __package__,
        root_path=basepath,
        static_folder=str(_FRONTEND_STATIC_ROOT),
        static_url_path="",
        template_folder=str(_FRONTEND_TEMPLATE_ROOT),
    )
