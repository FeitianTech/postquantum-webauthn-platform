"""On Cloud Run the app refuses to start without a shared session secret.

With ``K_SERVICE`` set and no ``FIDO_SERVER_SECRET_KEY`` or readable
``FIDO_SERVER_SECRET_KEY_FILE``, each instance used to generate its own key and
only log a warning; at ``maxScale: 10`` that invalidates sessions at random.
Local development keeps generating and persisting a key.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.app.config import session_secret
from server.app.factory import create_app


@pytest.fixture
def cloud_run(monkeypatch):
    monkeypatch.setenv("K_SERVICE", "pqcwebauthn")
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)


def test_cloud_run_without_a_secret_refuses_to_build_the_app(cloud_run, tmp_path):
    with pytest.raises(RuntimeError) as excinfo:
        session_secret._resolve_secret_key(SimpleNamespace(instance_path=str(tmp_path)))

    message = str(excinfo.value)
    assert "K_SERVICE" in message
    assert "FIDO_SERVER_SECRET_KEY" in message
    assert "FIDO_SERVER_SECRET_KEY_FILE" in message
    # Nothing was generated or stored on the way to refusing.
    assert list(tmp_path.iterdir()) == []

    with pytest.raises(RuntimeError, match="Refusing to start"):
        create_app()


def test_cloud_run_with_an_unreadable_secret_file_refuses(cloud_run, monkeypatch, tmp_path):
    missing = tmp_path / "missing.key"
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY_FILE", str(missing))

    with pytest.raises(RuntimeError, match="cannot be read"):
        session_secret._resolve_secret_key(SimpleNamespace(instance_path=str(tmp_path)))


def test_cloud_run_with_an_empty_secret_file_refuses(cloud_run, monkeypatch, tmp_path):
    empty = tmp_path / "empty.key"
    empty.write_bytes(b"")
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY_FILE", str(empty))

    with pytest.raises(RuntimeError, match="is empty"):
        session_secret._resolve_secret_key(SimpleNamespace(instance_path=str(tmp_path)))


def test_cloud_run_with_a_secret_starts(cloud_run, monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY", "shared-secret")
    assert create_app().secret_key == b"shared-secret"

    key_file = tmp_path / "secret.key"
    key_file.write_bytes(b"file-secret")
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY")
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY_FILE", str(key_file))
    assert create_app().secret_key == b"file-secret"

    # A secret passed to create_app() is used as is.
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE")
    assert create_app({"SECRET_KEY": "configured"}).secret_key == "configured"


def test_local_development_still_generates_and_persists_a_key(monkeypatch, tmp_path):
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)

    secret = session_secret._resolve_secret_key(SimpleNamespace(instance_path=str(tmp_path)))

    assert (tmp_path / "session-secret.key").read_bytes() == secret


def test_local_development_falls_back_when_the_secret_file_is_unreadable(monkeypatch, tmp_path):
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY_FILE", str(tmp_path / "missing.key"))
    warnings = []
    monkeypatch.setattr(session_secret.logger, "warning", lambda msg, *args: warnings.append(msg % args))

    secret = session_secret._resolve_secret_key(SimpleNamespace(instance_path=str(tmp_path)))

    assert (tmp_path / "session-secret.key").read_bytes() == secret
    assert len(warnings) == 1
    assert "cannot be read" in warnings[0]
