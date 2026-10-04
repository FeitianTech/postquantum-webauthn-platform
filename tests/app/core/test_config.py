"""Tests for the server/app/config package: the settings create_app() reads from the environment."""

from __future__ import annotations

import types

from server.app.config.attestation_trust import _parse_trusted_ca_subjects
from server.app.config.paths import basepath
from server.app.config.relying_party import (
    build_rp_entity,
    create_fido_server,
    determine_rp_id,
)
from server.app.config.session_secret import _resolve_secret_key
from server.app.factory import create_app
from server.app.mds import files as mds_files
from tests.app.entry_app import entry_app


def test_resolve_secret_key_from_env(monkeypatch):
    """Test secret key resolution from environment variable."""

    test_key = "test-secret-key"
    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY", test_key)

    # The environment is read when the app is built.
    app = create_app()

    assert app.secret_key == test_key.encode("utf-8")


def test_resolve_secret_key_from_file(tmp_path, monkeypatch):
    """Test secret key resolution from file."""
    # Create a temporary secret key file
    secret_file = tmp_path / "secret.key"
    secret_content = b"file-secret-key-content"
    secret_file.write_bytes(secret_content)


    monkeypatch.setenv("FIDO_SERVER_SECRET_KEY_FILE", str(secret_file))
    # The file is read only when no key is given directly.
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)

    app = create_app()

    assert app.secret_key == secret_content


def test_resolve_secret_key_generates_and_stores(tmp_path, monkeypatch):
    """Test that secret key is generated and stored when not provided."""
    # Set up a clean instance path
    instance_path = tmp_path / "instance"
    instance_path.mkdir()

    # Neither a key nor a key file: the tests' own secret is removed too.
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)


    secret = _resolve_secret_key(types.SimpleNamespace(instance_path=str(instance_path)))

    # Should have generated a key and stored it for the next start.
    assert len(secret) == 32
    assert (instance_path / "session-secret.key").read_bytes() == secret
    # A second resolution reads the stored key instead of generating one.
    assert _resolve_secret_key(types.SimpleNamespace(instance_path=str(instance_path))) == secret


def test_parse_trusted_ca_subjects():
    """Test parsing of trusted CA subjects."""
    
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
    
    # basepath should be a valid path (could be str or Path)
    assert basepath is not None
    # Convert to Path for validation
    from pathlib import Path
    path_obj = Path(basepath) if isinstance(basepath, str) else basepath
    assert path_obj.exists()


def test_mds_metadata_paths(monkeypatch):
    """The snapshot's files are absolute paths in one directory."""

    monkeypatch.delenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", raising=False)
    for name in mds_files.SNAPSHOT_FILENAMES:
        path = mds_files.snapshot_file(name)
        assert path.is_absolute()
        assert path.parent == mds_files.DEFAULT_SNAPSHOT_DIR


def test_create_fido_server():
    """Test that create_fido_server function works."""
    from fido2.server import Fido2Server

    
    with entry_app().app_context():
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
    from fido2.webauthn import PublicKeyCredentialRpEntity

    
    with entry_app().app_context():
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
    
    with entry_app().app_context():
        # Test with explicit ID
        rp_id = determine_rp_id("example.com")
        assert rp_id == "example.com"
    
        # Test without a request context (should return localhost)
        rp_id = determine_rp_id()
        assert rp_id == "localhost"


def test_determine_rp_id_with_request_context():
    """Test determine_rp_id with Flask request context."""
    
    with entry_app().test_request_context(
        "https://example.com/path",
        headers={"Host": "example.com"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "example.com"
    
    with entry_app().test_request_context(
        "https://test.example.com:8443/path",
        headers={"Host": "test.example.com:8443"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "test.example.com"
    
    # Test with IP addresses
    with entry_app().test_request_context(
        "http://127.0.0.1/path",
        headers={"Host": "127.0.0.1"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"
    
    # IPv6 localhost from a raw host value without brackets.
    with entry_app().test_request_context(
        "http://[::1]/path",
        headers={"Host": "::1"}  # Without brackets in header
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"

    # IPv6 localhost with the bracketed host:port form browsers send.
    with entry_app().test_request_context(
        "http://[::1]:8443/path",
        headers={"Host": "[::1]:8443"}
    ):
        rp_id = determine_rp_id()
        assert rp_id == "localhost"
