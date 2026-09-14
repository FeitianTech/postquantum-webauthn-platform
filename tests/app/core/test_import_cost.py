"""Guards against reintroducing heavy imports on the server start-up path."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_importing_app_does_not_load_google_cloud_libraries():
    env = dict(os.environ)
    env.pop("FIDO_SERVER_GCS_ENABLED", None)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_PROJECT_ROOT), env.get("PYTHONPATH")]))

    script = (
        "import sys\n"
        "import server.app.app\n"
        "loaded = sorted(name for name in sys.modules if name.startswith('google.cloud') "
        "or name.startswith('google.api_core'))\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )

    assert result.stdout.strip() == ""
