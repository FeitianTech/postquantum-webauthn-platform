"""Module-logger WARNINGs, and the operator modules' INFO, reach stderr, formatted,
under plain Python and gunicorn.

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

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SECRET = "logging-test-secret-0123456789abcdef"


def _flask_line(level: str, module: str, message: str) -> str:
    """A regex for one line in Flask's default_handler format.

    That format is "[%(asctime)s] %(levelname)s in %(module)s: %(message)s";
    logging.lastResort would print the bare message instead.
    """

    return r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}\] " + level + " in " + module + ": " + message


def _flask_warning(module: str, message: str) -> str:
    return _flask_line("WARNING", module, message)


def _env(tmp: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp),
        "PYTHONPATH": str(_REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "FIDO_SERVER_SECRET_KEY": _SECRET,
        "FIDO_SERVER_SESSION_METADATA_DIR": str(tmp / "runtime" / "session-metadata"),
        "FIDO_SERVER_CREDENTIAL_DIR": str(tmp / "credentials"),
        "FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR": str(tmp / "runtime" / "artifacts"),
        "FIDO_SERVER_MDS_SNAPSHOT_DIR": str(tmp / "mds-snapshot"),
        "FIDO_SERVER_MDS_FETCH_UPSTREAM": "0",
    }


def test_module_logger_warnings_reach_stderr_in_the_flask_format(tmp_path):
    code = (
        "import server.app.app\n"
        "from server.app.storage import credentials\n"
        "from server.app.webauthn import pqc\n"
        "credentials._decode_copy(b'not json', 'storage-probe')\n"
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

    storage = _flask_warning("credentials", r"Skipped undecodable credential data at storage-probe: ")
    assert re.search(storage, result.stderr, re.M), result.stderr
    # %(module)s names the calling code -- here the probe script, not pqc.py.
    assert re.search(_flask_warning("<string>", "pqc-probe$"), result.stderr, re.M), result.stderr
    # INFO stays below the effective level, as it did through app.logger.
    assert "pqc-info-probe" not in result.stderr


def test_the_operator_modules_info_reaches_stderr_and_a_route_s_does_not(tmp_path):
    code = (
        "import server.app.app\n"
        "from server.app.mds import provisioning\n"
        "from server.app.routes import mds\n"
        "from server.app.storage import github_mirror, github_outbox\n"
        "for module in (provisioning, github_mirror, github_outbox):\n"
        "    module.logger.info('info-probe %s', module.__name__)\n"
        "mds.logger.info('route-info-probe')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )

    for name in ("mds.provisioning", "storage.github_mirror", "storage.github_outbox"):
        probe = _flask_line("INFO", "<string>", rf"info-probe server\.app\.{re.escape(name)}$")
        assert re.search(probe, result.stderr, re.M), result.stderr
    assert "route-info-probe" not in result.stderr


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=30)
        self._unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(self._unix_path)
        self.sock = sock


def _request(sock_path: str, method: str, path: str, body: bytes | None = None) -> int:
    connection = _UnixHTTPConnection(sock_path)
    headers = {"Host": "localhost", "Content-Type": "application/csp-report"}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs unix sockets")
def test_module_logger_warning_and_provisioning_info_reach_gunicorn_stderr(tmp_path):
    """Real gunicorn, the repo's gunicorn.conf.py, real requests, a real warning and a real INFO line."""

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
    # One violation, which csp_reports logs as one WARNING line.
    report = (
        b'{"csp-report": {"effective-directive": "script-src-elem",'
        b' "blocked-uri": "inline", "document-uri": "http://localhost/probe"}}'
    )
    try:
        deadline = time.monotonic() + 30
        status = None
        while status is None:
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, "gunicorn did not start serving"
            try:
                status = _request(sock_path, "POST", "/api/csp-report", report)
            except OSError:
                time.sleep(0.1)
        assert status == 204
        # The snapshot directory is empty and the upstream refresh off: provisioning finds nothing.
        assert _request(sock_path, "GET", "/api/mds/metadata/info") == 200
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=30)
        shutil.rmtree(sock_dir, ignore_errors=True)

    warning = _flask_warning("csp_reports", r"CSP violation: directive=script-src-elem blocked=")
    assert re.search(warning, stderr, re.M), stderr
    provisioning = _flask_line("INFO", "provisioning", r"MDS snapshot files missing locally \(")
    assert re.search(provisioning, stderr, re.M), stderr
