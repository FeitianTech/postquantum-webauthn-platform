"""The checkout guard (``tests/checkout_guard.py``) sees every write into the paths it watches.

Each test runs pytest in a subprocess, with the guard rooted at a directory of
its own and a test module that writes into ``instance/`` there.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _run(root: Path, module: str) -> subprocess.CompletedProcess[str]:
    (root / "test_writes.py").write_text(module, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT)}
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            "-p", "tests.checkout_guard", f"--checkout-root={root}", f"--rootdir={root}", str(root),
        ],
        cwd=root, env=env, capture_output=True, text=True, timeout=120, check=False,
    )


_WRITES_WHILE_COLLECTED = '''
from pathlib import Path

(Path(__file__).parent / "instance").mkdir()
(Path(__file__).parent / "instance" / "session-secret.key").write_text("written on import")


def test_nothing():
    pass
'''

_WRITES_WHILE_RUNNING = '''
from pathlib import Path


def test_writes():
    (Path(__file__).parent / "instance").mkdir()
    (Path(__file__).parent / "instance" / "session-secret.key").write_text("written by a test")
'''


def test_a_write_made_by_a_test_fails_the_run(tmp_path):
    run = _run(tmp_path, _WRITES_WHILE_RUNNING)

    assert run.returncode != 0, run.stdout
    assert "instance/session-secret.key" in run.stdout


def test_a_write_made_while_the_tests_are_collected_fails_the_run(tmp_path):
    run = _run(tmp_path, _WRITES_WHILE_COLLECTED)

    # The guard lists the checkout before collection, when pytest is configured.
    assert run.returncode != 0, run.stdout
    assert "instance/session-secret.key" in run.stdout
