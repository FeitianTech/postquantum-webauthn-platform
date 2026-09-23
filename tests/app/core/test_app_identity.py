"""The app's name and instance path: what the logger hierarchy and the secret hang on."""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_instance_path_is_where_flask_derived_it_for_the_old_app_name(tmp_path):
    """Renaming the app must not move instance/session-secret.key.

    Flask derives the instance folder from the import name. The app is now named
    ``server.app`` and given the folder explicitly; it must be the folder Flask
    derived for the old name, ``server.app.config``. Checked in a clean process
    run from another directory, so neither the test suite's stub ``server``
    package nor Flask's cwd fallback can make the two agree by accident.
    """

    code = (
        "from flask import Flask\n"
        "from server.app.config import app, paths\n"
        "legacy = Flask('server.app.config', root_path=paths.basepath)\n"
        "print(legacy.instance_path)\n"
        "print(paths.INSTANCE_ROOT)\n"
        "print(app.instance_path)\n"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(_REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "FIDO_SERVER_SECRET_KEY": "instance-path-test-secret",
        "FIDO_SERVER_RUNTIME_ROOT": str(tmp_path / "runtime"),
        "FIDO_SERVER_SESSION_METADATA_DIR": str(tmp_path / "runtime" / "session-metadata"),
    }
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )

    legacy, pinned, actual = result.stdout.split()
    assert legacy == str(_REPO_ROOT / "instance")
    assert pinned == legacy
    assert actual == legacy


def test_app_logger_is_an_ancestor_of_every_module_logger():
    app = pytest.importorskip("server.app.config").app

    assert app.logger.name == "server.app"
    for name in ("server.app.storage.credentials", "server.app.webauthn.pqc", "server.app.routes.general"):
        logger = logging.getLogger(name)
        ancestors = []
        while logger is not None:
            ancestors.append(logger)
            logger = logger.parent
        assert app.logger in ancestors, name
