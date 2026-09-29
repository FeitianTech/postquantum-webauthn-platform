"""A credential directory the store creates is ignored by git, wherever it is.

``FIDO_SERVER_CREDENTIAL_DIR`` may name a folder inside a checkout, where the
repository's .gitignore (which covers ``instance/``) does not reach.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest


@pytest.fixture
def store_in(monkeypatch, storage_module):
    def _point(root):
        monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(root))
        monkeypatch.setattr(storage_module, "_using_gcs", lambda: False)
        return storage_module

    return _point


def test_the_store_root_gets_a_gitignore_that_ignores_everything(tmp_path, store_in):
    store = store_in(tmp_path / "credentials")

    store.savekey("alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    lines = (tmp_path / "credentials" / ".gitignore").read_text().splitlines()
    assert "*" in lines
    assert store.readkey("alice@example.com", session_id="session-a") == [{"credential_data": "x"}]


def test_a_gitignore_already_there_is_kept(tmp_path, store_in):
    root = tmp_path / "credentials"
    root.mkdir()
    (root / ".gitignore").write_text("mine\n")
    store = store_in(root)

    store.savekey("alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    assert (root / ".gitignore").read_text() == "mine\n"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_offers_nothing_of_a_store_inside_a_checkout(tmp_path, store_in):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    store = store_in(checkout / "my-credentials")

    store.savekey("alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""
