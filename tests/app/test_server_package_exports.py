from __future__ import annotations

import importlib
import sys


def test_server_package_defers_app_module_import_until_export_access():
    sys.modules.pop("server.app", None)
    sys.modules.pop("server.app.app", None)

    package = importlib.import_module("server.app")
    assert "server.app.app" not in sys.modules

    _ = package.app
    assert "server.app.app" in sys.modules


def test_server_package_exports_app_and_main_contract():
    package_init = importlib.import_module("server.app")
    module = importlib.import_module("server.app.app")

    assert package_init.app is module.app
    assert package_init.main is module.main
    assert sorted(package_init.__all__) == ["app", "main"]
    assert module.app.__class__.__name__ == "Flask"
