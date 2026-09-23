"""Importing server code writes nothing to disk.

The old import-time app wrote ``instance/session-secret.key`` and created the
session-metadata directory as soon as ``server.app.config`` was imported. Now
only building an app may write, so every module is imported here in a fresh
interpreter with an audit hook that records each filesystem write.

``server.app.app`` is the one module left out: it is the composition root, and
importing it runs ``create_app()``. It is then imported with a session secret
configured -- the production shape -- where it must write nothing either.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]

_PROBE = r"""
import importlib
import json
import os
import pkgutil
import runpy
import sys

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
WRITE_EVENTS = {
    "os.chmod", "os.link", "os.mkdir", "os.remove", "os.rename", "os.rmdir",
    "os.symlink", "os.truncate", "os.utime", "shutil.copyfile", "shutil.copytree",
    "shutil.move", "shutil.rmtree", "tempfile.mkdtemp", "tempfile.mkstemp",
}
writes = []


def audit(event, args):
    if event == "open":
        path, mode, flags = args
        if isinstance(mode, str):
            if any(c in mode for c in "wax+"):
                writes.append([event, str(path), mode])
        elif isinstance(flags, int) and flags & WRITE_FLAGS:
            writes.append([event, str(path), flags])
    elif event in WRITE_EVENTS:
        writes.append([event, repr(args)])


sys.addaudithook(audit)

import server.app
import tools

modules = []
for package in (server.app, tools):
    for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if info.name == "server.app.app":
            continue
        importlib.import_module(info.name)
        modules.append(info.name)
runpy.run_path("gunicorn.conf.py")
modules.append("gunicorn.conf.py")
import_writes = list(writes)

writes.clear()
os.environ["FIDO_SERVER_SECRET_KEY"] = "import-probe-secret"
importlib.import_module("server.app.app")
entry_point_writes = list(writes)

print(json.dumps({
    "modules": modules,
    "import_writes": import_writes,
    "entry_point_writes": entry_point_writes,
}))
"""


def test_importing_every_server_module_writes_nothing(tmp_path):
    # Only what the interpreter needs: no secret, no K_SERVICE, no runtime dirs.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(_REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])

    assert len(report["modules"]) > 80
    assert "server.app.config" in report["modules"]
    assert "server.app.config.session_secret" in report["modules"]
    assert "server.app.storage.session_metadata" in report["modules"]
    assert "server.app.factory" in report["modules"]
    assert "tools.update_mds_snapshot" in report["modules"]
    assert report["import_writes"] == []
    assert report["entry_point_writes"] == []
