"""``config.paths``: the package directory, and the instance folder beside ``server/``."""
from __future__ import annotations

from pathlib import Path

from server.app.config import paths


def test_the_instance_folder_sits_at_the_project_root_beside_server():
    package = Path(paths.basepath)

    assert package.parts[-2:] == ("server", "app")
    assert (package / "config" / "paths.py").is_file()
    assert Path(paths.INSTANCE_ROOT) == package.parents[1] / "instance"


def test_each_local_store_has_its_setting_and_its_folder_under_the_instance(monkeypatch):
    for setting, folder in paths.LOCAL_STORES:
        monkeypatch.delenv(setting, raising=False)
        assert paths.store_dir(setting, folder) == str(Path(paths.INSTANCE_ROOT) / folder)
    assert [setting for setting, _folder in paths.LOCAL_STORES] == [
        "FIDO_SERVER_SESSION_METADATA_DIR",
        "FIDO_SERVER_CREDENTIAL_DIR",
        "FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR",
    ]
