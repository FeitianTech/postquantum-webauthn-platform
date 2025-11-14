"""Test coverage for server.server.__init__ module."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

# Setup module structure before any imports
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


def test_server_init_module_import():
    """Test that server.__init__ module code is valid Python."""
    # Read the __init__.py content
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    
    # Verify it compiles without errors
    compile(content, str(init_file), 'exec')
    
    # Verify it has the expected structure
    assert "from __future__ import annotations" in content
    assert "from .app import app, main" in content
    assert '__all__' in content


def test_server_init_has_annotations_import():
    """Test that __future__ annotations import exists."""
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    assert "from __future__ import annotations" in content


def test_server_init_imports_from_app():
    """Test that server.__init__ imports from app module."""
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    assert "from .app import app, main" in content


def test_server_init_defines_all():
    """Test that server.__init__ defines __all__."""
    from pathlib import Path
    init_file = Path(__file__).parents[1] / "server" / "server" / "__init__.py"
    content = init_file.read_text()
    assert '__all__ = ["app", "main"]' in content
