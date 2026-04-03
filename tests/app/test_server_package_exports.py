from __future__ import annotations

import importlib


def test_server_package_exports_app_and_main_contract():
    package_init = importlib.import_module("server.app.__init__")
    module = importlib.import_module("server.app.app")

    assert package_init.app is module.app
    assert package_init.main is module.main
    assert sorted(package_init.__all__) == ["app", "main"]
    assert module.app.__class__.__name__ == "Flask"
