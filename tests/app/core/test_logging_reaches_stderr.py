"""Module-logger WARNINGs reach stderr, formatted, under plain Python and gunicorn.

Modules log through ``logging.getLogger(__name__)``. Those loggers have no
handler of their own; they reach stderr only because ``create_app()`` attaches
Flask's handler to their parent, ``app.logger`` (``server.app``). Gunicorn
configures no root handler here, so if that chain broke, records would fall
through to ``logging.lastResort``: unformatted, and nothing below WARNING. These
tests run in fresh processes because pytest's own log capture would otherwise
stand in for the missing handler.
"""
from __future__ import annotations

import http.client
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from itsdangerous import URLSafeTimedSerializer

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SECRET = "logging-test-secret-0123456789abcdef"


def _flask_warning(module: str, message: str) -> str:
    """A regex for one WARNING line in Flask's default_handler format.

    That format is "[%(asctime)s] %(levelname)s in %(module)s: %(message)s";
    logging.lastResort would print the bare message instead.
    """

    return r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}\] WARNING in " + module + ": " + message


def _env(tmp: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp),
        "PYTHONPATH": str(_REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "FIDO_SERVER_SECRET_KEY": _SECRET,
        "FIDO_SERVER_RUNTIME_ROOT": str(tmp / "runtime"),
        "FIDO_SERVER_SESSION_METADATA_DIR": str(tmp / "runtime" / "session-metadata"),
        "FIDO_SERVER_CREDENTIAL_DIR": str(tmp / "credentials"),
        "FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR": str(tmp / "runtime" / "artifacts"),
    }


def test_module_logger_warnings_reach_stderr_in_the_flask_format(tmp_path):
    code = (
        "import server.app.app\n"
        "from server.app.storage import record_format\n"
        "from server.app.webauthn import pqc\n"
        "record_format.load_payload(b'not json', source='storage-probe')\n"
        "pqc.logger.warning('pqc-probe')\n"
        "pqc.logger.info('pqc-info-probe')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )

    storage = _flask_warning(
        "record_format", r"(Ignoring non-JSON|Unable to read legacy) credential payload at storage-probe"
    )
    assert re.search(storage, result.stderr, re.M), result.stderr
    # %(module)s names the calling code -- here the probe script, not pqc.py.
    assert re.search(_flask_warning("<string>", "pqc-probe$"), result.stderr, re.M), result.stderr
    # INFO stays below the effective level, as it did through app.logger.
    assert "pqc-info-probe" not in result.stderr


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=30)
        self._unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(self._unix_path)
        self.sock = sock


def _get(sock_path: str, path: str, cookie: str | None = None):
    connection = _UnixHTTPConnection(sock_path)
    headers = {"Host": "localhost"}
    if cookie:
        headers["Cookie"] = cookie
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    response.read()
    cookies = response.headers.get_all("Set-Cookie") or []
    connection.close()
    return response.status, cookies


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs unix sockets")
def test_storage_warning_reaches_gunicorn_stderr(tmp_path):
    """Real gunicorn, the repo's gunicorn.conf.py, a real request, a real warning."""

    pytest.importorskip("gunicorn")
    # macOS limits unix socket paths to 104 bytes; pytest's tmp_path can be longer.
    sock_dir = tempfile.mkdtemp(prefix="gunicorn-", dir="/tmp" if os.path.isdir("/tmp") else None)
    sock_path = os.path.join(sock_dir, "g.sock")
    env = _env(tmp_path)
    env["GUNICORN_THREADS"] = "2"
    process = subprocess.Popen(
        [
            sys.executable, "-m", "gunicorn",
            "-c", "gunicorn.conf.py",
            "--bind", f"unix:{sock_path}",
            "server.app.app:app",
        ],
        cwd=_REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        status = cookies = None
        while status is None:
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, "gunicorn did not start serving"
            try:
                status, cookies = _get(sock_path, "/api/downloadcred?email=probe")
            except OSError:
                time.sleep(0.1)
        assert status == 404

        # The first request minted a metadata session; plant a credential file the
        # store cannot parse in it, and ask for it again.
        jar = dict(raw.split(";", 1)[0].split("=", 1) for raw in cookies)
        session_id = URLSafeTimedSerializer(_SECRET, salt="fido.mds.session-cookie.v1").loads(
            jar["fido.mds.session"]
        )
        target = tmp_path / "credentials" / session_id / "probe_credential_data.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"this is not json")

        status, _ = _get(
            sock_path,
            "/api/downloadcred?email=probe",
            cookie="; ".join(f"{name}={value}" for name, value in jar.items()),
        )
        assert status == 404
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=30)
        shutil.rmtree(sock_dir, ignore_errors=True)

    warning = _flask_warning(
        "record_format",
        r"(Ignoring non-JSON|Unable to read legacy) credential payload at .*probe_credential_data\.json",
    )
    assert re.search(warning, stderr, re.M), stderr
