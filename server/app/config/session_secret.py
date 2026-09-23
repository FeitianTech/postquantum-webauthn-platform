"""The Flask session secret, resolved when this module is imported.

In order: ``FIDO_SERVER_SECRET_KEY``, the file named by
``FIDO_SERVER_SECRET_KEY_FILE``, then ``<instance_path>/session-secret.key`` --
which is generated and written on first use, so importing this module can write
to disk.
"""
from __future__ import annotations

import os
import tempfile

from .application import app


def _resolve_secret_key() -> bytes:
    """Return the Flask session secret."""

    env_value = os.environ.get("FIDO_SERVER_SECRET_KEY")
    if isinstance(env_value, str) and env_value:
        return env_value.encode("utf-8")

    file_path = os.environ.get("FIDO_SERVER_SECRET_KEY_FILE")
    if isinstance(file_path, str) and file_path:
        try:
            with open(file_path, "rb") as key_file:
                file_value = key_file.read()
                if file_value:
                    return file_value
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning(
                "Unable to read secret key file %s: %s", file_path, exc
            )

    default_path = os.path.join(app.instance_path, "session-secret.key")

    def _read_stored_key() -> bytes | None:
        try:
            with open(default_path, "rb") as stored_key:
                stored_value = stored_key.read()
                if stored_value:
                    return stored_value
        except FileNotFoundError:
            return None
        except OSError:
            return None
        return None

    stored = _read_stored_key()
    if stored:
        return stored

    secret = os.urandom(32)

    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret

    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="session-secret.", dir=os.path.dirname(default_path)
        )
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(secret)
            target.flush()
            os.fsync(target.fileno())
        try:
            os.replace(temp_path, default_path)
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning("Unable to store generated session secret: %s", exc)
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    stored = _read_stored_key()
    if stored:
        return stored

    return secret


app.secret_key = _resolve_secret_key()
