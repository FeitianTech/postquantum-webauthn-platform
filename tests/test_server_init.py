"""Tests for server package initialization and app module."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

# Setup module structure
server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.server")
server_server_pkg.__path__ = [str(_ROOT / "server" / "server")]
sys.modules.setdefault("server.server", server_server_pkg)


@pytest.fixture(autouse=True)
def _mock_dependencies(monkeypatch):
    """Mock Google Cloud Storage dependencies for all tests."""
    # Setup google.api_core
    google_pkg = types.ModuleType("google")
    google_pkg.__path__ = []
    sys.modules.setdefault("google", google_pkg)

    google_api_core_pkg = types.ModuleType("google.api_core")
    google_api_core_pkg.__path__ = []
    sys.modules.setdefault("google.api_core", google_api_core_pkg)

    google_api_core_exceptions_pkg = types.ModuleType("google.api_core.exceptions")
    setattr(google_api_core_exceptions_pkg, "NotFound", Exception)
    setattr(google_api_core_exceptions_pkg, "GoogleAPICallError", Exception)
    setattr(google_api_core_exceptions_pkg, "RetryError", Exception)
    sys.modules.setdefault("google.api_core.exceptions", google_api_core_exceptions_pkg)

    google_cloud_pkg = types.ModuleType("google.cloud")
    google_cloud_pkg.__path__ = []
    sys.modules.setdefault("google.cloud", google_cloud_pkg)

    class _DummyClient:
        def bucket(self, *_args, **_kwargs):
            raise RuntimeError("Not configured")

    google_cloud_storage_pkg = types.ModuleType("google.cloud.storage")
    setattr(google_cloud_storage_pkg, "Client", _DummyClient)
    sys.modules.setdefault("google.cloud.storage", google_cloud_storage_pkg)

    google_oauth_pkg = types.ModuleType("google.oauth2")
    google_oauth_pkg.__path__ = []
    sys.modules.setdefault("google.oauth2", google_oauth_pkg)

    class _DummyCredentials:
        @classmethod
        def from_service_account_file(cls, *_args, **_kwargs):
            return cls()

        @classmethod
        def from_service_account_info(cls, *_args, **_kwargs):
            return cls()

    google_service_account_pkg = types.ModuleType("google.oauth2.service_account")
    setattr(google_service_account_pkg, "Credentials", _DummyCredentials)
    sys.modules.setdefault("google.oauth2.service_account", google_service_account_pkg)

    google_auth_pkg = types.ModuleType("google.auth")
    google_auth_pkg.__path__ = []
    sys.modules.setdefault("google.auth", google_auth_pkg)

    google_auth_exceptions_pkg = types.ModuleType("google.auth.exceptions")
    setattr(google_auth_exceptions_pkg, "RefreshError", Exception)
    sys.modules.setdefault("google.auth.exceptions", google_auth_exceptions_pkg)

    google_pkg.api_core = google_api_core_pkg
    google_pkg.cloud = google_cloud_pkg
    google_pkg.oauth2 = google_oauth_pkg
    google_api_core_pkg.exceptions = google_api_core_exceptions_pkg
    google_cloud_pkg.storage = google_cloud_storage_pkg
    google_oauth_pkg.service_account = google_service_account_pkg
    google_auth_pkg.exceptions = google_auth_exceptions_pkg


def test_server_init_imports():
    """Test that server.__init__ can be imported and exposes correct exports."""
    # Just verify that the file content is correct
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    
    # Verify imports are present
    assert "from __future__ import annotations" in content
    assert "from .app import app, main" in content
    assert '__all__ = ["app", "main"]' in content


def test_server_init_module_exports():
    """Test that server.__init__.__all__ is correct."""
    # Read the __init__.py source directly to check __all__
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    
    # Verify that __all__ is defined correctly
    assert '__all__ = ["app", "main"]' in content
    # Verify that it imports from .app
    assert "from .app import app, main" in content


def test_app_module_imports():
    """Test that app module can be imported."""
    from server.server import app as server_app
    
    # The app module defines 'app' and 'main'
    assert server_app is not None


def test_app_discover_project_root():
    """Test the _discover_project_root function."""
    from server.server.app import _discover_project_root
    import pathlib
    
    # Test with actual package root
    package_root = pathlib.Path(__file__).resolve().parents[1] / "server" / "server"
    result = _discover_project_root(package_root)
    
    # Should find the project root containing fido2 directory
    assert (result / "fido2").is_dir()


def test_app_discover_project_root_fallback(monkeypatch):
    """Test _discover_project_root fallback behavior."""
    from server.server.app import _discover_project_root
    import pathlib
    
    # Create a temporary path that doesn't have fido2
    temp_path = pathlib.Path("/tmp/test_fallback")
    
    # Mock is_dir to always return False
    original_is_dir = pathlib.Path.is_dir
    
    def mock_is_dir(self):
        if self.name == "fido2":
            return False
        return original_is_dir(self)
    
    monkeypatch.setattr(pathlib.Path, "is_dir", mock_is_dir)
    
    # Should fall back to grandparent
    result = _discover_project_root(temp_path)
    assert result == temp_path.parents[1]


def test_app_import_module():
    """Test the _import_module function."""
    from server.server.app import _import_module
    
    # Should successfully import a real module
    sys_module = _import_module("sys")
    assert sys_module is sys


def test_app_import_module_not_found():
    """Test _import_module with non-existent module."""
    from server.server.app import _import_module
    
    with pytest.raises(ModuleNotFoundError) as exc_info:
        _import_module("nonexistent_module_xyz_123")
    
    assert "Unable to import" in str(exc_info.value)
    assert "nonexistent_module_xyz_123" in str(exc_info.value)


def test_app_main_function_structure():
    """Test that the main() function exists and has the correct structure."""
    from pathlib import Path
    app_file = Path(__file__).parents[1] / "server" / "server" / "app.py"
    content = app_file.read_text()
    
    # Verify main function exists and has correct structure
    assert "def main() -> None:" in content
    assert "ensure_metadata = getattr(general," in content
    assert 'app.run(' in content
    assert 'host="demo.ftsafe.demo"' in content
    assert 'port=5000' in content


def test_app_main_without_ensure_metadata(monkeypatch):
    """Test main() function can be called (without actually running the server)."""
    import sys
    import server.server.app as app_module_raw
    
    # Get the actual Flask app from config
    from server.server.config import app as flask_app_obj
    
    # Mock app.run to prevent actual server start
    mock_run_called = []
    
    def mock_run(**kwargs):
        mock_run_called.append(kwargs)
    
    monkeypatch.setattr(flask_app_obj, "run", mock_run)
    
    # Get general module and mock it
    if "server.server.routes.general" in sys.modules:
        general_module = sys.modules["server.server.routes.general"]
    else:
        general_module = types.ModuleType("server.server.routes.general")
        sys.modules["server.server.routes.general"] = general_module
    
    # Add ensure_metadata_bootstrapped
    general_module.ensure_metadata_bootstrapped = lambda **kwargs: None
    
    # Call main
    app_module_raw.main()
    
    # Verify app.run was called
    assert len(mock_run_called) == 1
    assert mock_run_called[0]["host"] == "demo.ftsafe.demo"


def test_app_all_exports():
    """Test that app module __all__ is correct."""
    # Read the app.py source directly to check __all__
    from pathlib import Path
    app_file = Path(__file__).parents[1] / "server" / "server" / "app.py"
    content = app_file.read_text()
    
    # Verify __all__ is defined
    assert '__all__ = ["app", "main"]' in content


def test_app_module_level_imports():
    """Test module-level imports in app.py."""
    # Import the actual module, not the Flask app object
    import importlib
    app_module = importlib.import_module("server.server.app")
    
    # Should have imported these at module level
    assert hasattr(app_module, "app")
    assert hasattr(app_module, "main")
    assert hasattr(app_module, "_PROJECT_ROOT")
    assert hasattr(app_module, "_PACKAGE_ROOT")
