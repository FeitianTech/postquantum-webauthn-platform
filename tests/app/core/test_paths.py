"""``config.paths``: the package directory, and the instance folder beside ``server/``."""
from __future__ import annotations

from pathlib import Path

from server.app.config import paths


def test_the_instance_folder_sits_at_the_project_root_beside_server():
    package = Path(paths.basepath)

    assert package.parts[-2:] == ("server", "app")
    assert (package / "config" / "paths.py").is_file()
    assert Path(paths.INSTANCE_ROOT) == package.parents[1] / "instance"
