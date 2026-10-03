"""A local store's folder is ignored by git, wherever it is.

``FIDO_SERVER_CREDENTIAL_DIR``, ``FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR`` and
``FIDO_SERVER_SESSION_METADATA_DIR`` may each name a folder inside a checkout,
where the repository's .gitignore (which covers ``instance/``) does not reach.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from server.app.storage import common as storage_common
from server.app.storage import credential_artifacts, session_metadata
from server.app.storage import credentials as storage_credentials
from tests.app.storage.credential_seed import seed_records


@pytest.fixture
def store_in(monkeypatch):
    def _point(root):
        monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(root))
        monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
        return storage_credentials

    return _point


def test_the_store_root_gets_a_gitignore_that_ignores_everything(tmp_path, store_in):
    store = store_in(tmp_path / "credentials")

    seed_records(store, "alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    lines = (tmp_path / "credentials" / ".gitignore").read_text().splitlines()
    assert "*" in lines
    assert store.readkey("alice@example.com", session_id="session-a") == [{"credential_data": "x"}]


def test_a_gitignore_already_there_is_kept(tmp_path, store_in):
    root = tmp_path / "credentials"
    root.mkdir()
    (root / ".gitignore").write_text("mine\n")
    store = store_in(root)

    seed_records(store, "alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    assert (root / ".gitignore").read_text() == "mine\n"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_offers_nothing_of_a_store_inside_a_checkout(tmp_path, store_in):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    store = store_in(checkout / "my-credentials")

    seed_records(store, "alice@example.com", [{"credential_data": "x"}], session_id="session-a")

    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""


def _store_a_credential(store_root, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(store_root))
    seed_records(storage_credentials, "alice@example.com", [{"credential_data": "x"}], session_id="session-a")


def _store_an_artifact(store_root, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(store_root))
    assert credential_artifacts.store_credential_artifact("cred-1", {"kept": True}, session_id="session-a")


def _store_an_upload(store_root, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(store_root))
    session_metadata.write_file("session-a", "upload.json", b"{}")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
@pytest.mark.parametrize("store", [_store_a_credential, _store_an_artifact, _store_an_upload])
def test_git_offers_nothing_of_any_store_inside_a_checkout(tmp_path, monkeypatch, store):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)

    store(checkout / "my-store", monkeypatch)

    assert any((checkout / "my-store").rglob("*.json"))
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""
