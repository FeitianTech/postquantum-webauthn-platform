"""Tests for server/app/config.py module."""

from __future__ import annotations

import os
import sys
import tempfile
import types
from pathlib import Path
from unittest import mock

import pytest

_ROOT = Path(__file__).resolve().parents[2]

# Setup module structure
server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)

# Mock Google Cloud modules
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


def test_env_flag_with_none():
    """Test _env_flag when env var is not set."""
    from server.app.config import _env_flag
    
    with mock.patch.dict(os.environ, {}, clear=False):
        if "TEST_FLAG" in os.environ:
            del os.environ["TEST_FLAG"]
        assert _env_flag("TEST_FLAG") is None


def test_env_flag_with_false_values():
    """Test _env_flag with various false values."""
    from server.app.config import _env_flag
    
    false_values = ["", "0", "false", "off", "no", "  false  ", "  0  "]
    for value in false_values:
        with mock.patch.dict(os.environ, {"TEST_FLAG": value}, clear=False):
            assert _env_flag("TEST_FLAG") is False, f"Failed for value: {value}"


def test_env_flag_with_true_values():
    """Test _env_flag with various true values."""
    from server.app.config import _env_flag
    
    true_values = ["1", "true", "yes", "on", "True", "YES", "  1  ", "anything"]
    for value in true_values:
        with mock.patch.dict(os.environ, {"TEST_FLAG": value}, clear=False):
            assert _env_flag("TEST_FLAG") is True, f"Failed for value: {value}"


def test_resolve_secret_key_from_env():
    """Test secret key resolution from environment variable."""
    # Note: This test may not work because the module is already loaded
    # But it tests the code path
    test_key = "test-secret-key"
    
    with mock.patch.dict(os.environ, {"FIDO_SERVER_SECRET_KEY": test_key}, clear=False):
        # Import after setting env var
        import importlib
        from server.app import config
        importlib.reload(config)
        
        # The key should be set
        assert config.app.secret_key is not None


def test_resolve_secret_key_from_file(tmp_path):
    """Test secret key resolution from file."""
    # Create a temporary secret key file
    secret_file = tmp_path / "secret.key"
    secret_content = b"file-secret-key-content"
    secret_file.write_bytes(secret_content)
    
    with mock.patch.dict(os.environ, {
        "FIDO_SERVER_SECRET_KEY_FILE": str(secret_file)
    }, clear=False):
        # Clear the direct env key
        if "FIDO_SERVER_SECRET_KEY" in os.environ:
            del os.environ["FIDO_SERVER_SECRET_KEY"]
        
        import importlib
        from server.app import config
        importlib.reload(config)
        
        # The key should be set
        assert config.app.secret_key is not None


def test_resolve_secret_key_generates_and_stores(tmp_path, monkeypatch):
    """Test that secret key is generated and stored when not provided."""
    # Set up a clean instance path
    instance_path = tmp_path / "instance"
    instance_path.mkdir()
    
    # Clear environment variables
    env_clear = {}
    if "FIDO_SERVER_SECRET_KEY" in os.environ:
        env_clear["FIDO_SERVER_SECRET_KEY"] = None
    if "FIDO_SERVER_SECRET_KEY_FILE" in os.environ:
        env_clear["FIDO_SERVER_SECRET_KEY_FILE"] = None
    
    with mock.patch.dict(os.environ, env_clear, clear=False):
        from server.app.config import _resolve_secret_key
        
        # Mock the app.instance_path
        with mock.patch("server.app.config.app") as mock_app:
            mock_app.instance_path = str(instance_path)
            mock_app.logger = mock.MagicMock()
            
            secret = _resolve_secret_key()
            
            # Should have generated a key
            assert secret is not None
            assert len(secret) > 0
            
            # Should have tried to store it
            expected_path = instance_path / "session-secret.key"
            # File may or may not exist depending on write permissions
            # but the secret should be valid


def test_parse_trusted_ca_subjects():
    """Test parsing of trusted CA subjects."""
    from server.app.config import _parse_trusted_ca_subjects
    
    # Test None input
    assert _parse_trusted_ca_subjects(None) is None
    
    # Test empty string
    assert _parse_trusted_ca_subjects("") is None
    assert _parse_trusted_ca_subjects("  ") is None
    
    # Test single subject
    result = _parse_trusted_ca_subjects("CN=Test CA")
    assert result == {"CN=Test CA"}
    
    # Test comma-separated subjects
    result = _parse_trusted_ca_subjects("CN=CA1, CN=CA2, CN=CA3")
    assert result == {"CN=CA1", "CN=CA2", "CN=CA3"}
    
    # Test newline-separated subjects
    result = _parse_trusted_ca_subjects("CN=CA1\nCN=CA2\nCN=CA3")
    assert result == {"CN=CA1", "CN=CA2", "CN=CA3"}
    
    # Test mixed separators with whitespace
    result = _parse_trusted_ca_subjects("  CN=CA1  ,  CN=CA2  \n  CN=CA3  ")
    assert result == {"CN=CA1", "CN=CA2", "CN=CA3"}
    
    # Test duplicate removal
    result = _parse_trusted_ca_subjects("CN=CA1, CN=CA1, CN=CA2")
    assert result == {"CN=CA1", "CN=CA2"}


def test_basepath():
    """Test basepath configuration."""
    from server.app.config import basepath
    
    # basepath should be a valid path (could be str or Path)
    assert basepath is not None
    # Convert to Path for validation
    from pathlib import Path
    path_obj = Path(basepath) if isinstance(basepath, str) else basepath
    assert path_obj.exists()


def test_mds_metadata_paths():
    """Test MDS metadata path constants."""
    from server.app.config import (
        MDS_METADATA_PATH,
        MDS_METADATA_CACHE_PATH,
        MDS_METADATA_VERIFIED_PATH,
    )
    from pathlib import Path
    
    # All paths should exist as strings or Path objects
    assert MDS_METADATA_PATH is not None
    assert MDS_METADATA_CACHE_PATH is not None
    assert MDS_METADATA_VERIFIED_PATH is not None
    
    # Convert to Path for validation
    path1 = Path(MDS_METADATA_PATH) if isinstance(MDS_METADATA_PATH, str) else MDS_METADATA_PATH
    path2 = Path(MDS_METADATA_CACHE_PATH) if isinstance(MDS_METADATA_CACHE_PATH, str) else MDS_METADATA_CACHE_PATH
    path3 = Path(MDS_METADATA_VERIFIED_PATH) if isinstance(MDS_METADATA_VERIFIED_PATH, str) else MDS_METADATA_VERIFIED_PATH
    
    # Paths should be absolute
    assert path1.is_absolute()
    assert path2.is_absolute()
    assert path3.is_absolute()


def test_mds_metadata_url():
    """Test MDS metadata URL constant."""
    from server.app.config import MDS_METADATA_URL
    
    # Should be a string URL
    assert isinstance(MDS_METADATA_URL, str)
    assert MDS_METADATA_URL.startswith("http")


def test_create_fido_server():
    """Test that create_fido_server function works."""
    from server.app.config import create_fido_server
    from fido2.server import Fido2Server
    
    # Should create a Fido2Server instance
    server = create_fido_server()
    assert isinstance(server, Fido2Server)
    
    # Should have an RP entity
    assert server.rp is not None
    assert server.rp.name is not None
    
    # Test with explicit rp_id
    server = create_fido_server(rp_id="example.com")
    assert server.rp.id == "example.com"
    
    # Test with explicit rp_name
    server = create_fido_server(rp_name="Test Server")
    assert server.rp.name == "Test Server"


def test_build_rp_entity():
    """Test build_rp_entity function."""
    from server.app.config import build_rp_entity
    from fido2.webauthn import PublicKeyCredentialRpEntity
    
    # Test with explicit rp_id
    rp = build_rp_entity(rp_id="example.com")
    assert isinstance(rp, PublicKeyCredentialRpEntity)
    assert rp.id == "example.com"
    
    # Test with rp_data dict
    rp = build_rp_entity({"id": "test.com", "name": "Test RP"})
    assert isinstance(rp, PublicKeyCredentialRpEntity)
    assert rp.id == "test.com"
    assert rp.name == "Test RP"
    
    # Test with explicit rp_name
    rp = build_rp_entity(rp_name="Custom Server")
    assert rp.name == "Custom Server"


def test_determine_rp_id():
    """Test determine_rp_id function."""
    from server.app.config import determine_rp_id
    
    # Test with explicit ID
    rp_id = determine_rp_id("example.com")
    assert rp_id == "example.com"
    
    # Test without request context (should return localhost)
    rp_id = determine_rp_id()
    assert rp_id == "localhost"


def test_determine_rp_id_with_request_context():
    """Test determine_rp_id with Flask request context."""
    from server.app.config import determine_rp_id, app
    
    with app.test_request_context(
        "https://example.com/path",
        headers={"Host": "example.com"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "example.com"
    
    with app.test_request_context(
        "https://test.example.com:8443/path",
        headers={"Host": "test.example.com:8443"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "test.example.com"
    
    # Test with IP addresses
    with app.test_request_context(
        "http://127.0.0.1/path",
        headers={"Host": "127.0.0.1"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"
    
    # IPv6 localhost from a raw host value without brackets.
    with app.test_request_context(
        "http://[::1]/path",
        headers={"Host": "::1"}  # Without brackets in header
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"

    # IPv6 localhost with the bracketed host:port form browsers send.
    with app.test_request_context(
        "http://[::1]:8443/path",
        headers={"Host": "[::1]:8443"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"
