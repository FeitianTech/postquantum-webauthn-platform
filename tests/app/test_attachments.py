"""Tests for authenticator attachment helpers."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

# Setup module structure
server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)


@pytest.fixture(autouse=True)
def _mock_dependencies(monkeypatch):
    """Mock Google Cloud Storage dependencies for all tests."""
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


def test_hint_to_attachment_map():
    """Test that the hint-to-attachment mapping is correctly defined."""
    from server.app import attachments
    
    assert attachments.HINT_TO_ATTACHMENT_MAP == {
        "security-key": "cross-platform",
        "hybrid": "cross-platform",
        "client-device": "platform",
    }


def test_normalize_attachment_with_string():
    """Test normalizing valid attachment strings."""
    from server.app import attachments
    
    assert attachments.normalize_attachment("platform") == "platform"
    assert attachments.normalize_attachment("cross-platform") == "cross-platform"
    assert attachments.normalize_attachment("  Platform  ") == "platform"
    assert attachments.normalize_attachment("CROSS-PLATFORM") == "cross-platform"


def test_normalize_attachment_with_empty():
    """Test normalizing empty or whitespace-only strings."""
    from server.app import attachments
    
    assert attachments.normalize_attachment("") is None
    assert attachments.normalize_attachment("   ") is None


def test_normalize_attachment_with_non_string():
    """Test normalizing non-string values."""
    from server.app import attachments
    
    assert attachments.normalize_attachment(None) is None
    assert attachments.normalize_attachment(123) is None
    assert attachments.normalize_attachment([]) is None
    assert attachments.normalize_attachment({}) is None


def test_derive_allowed_attachments_from_hints_security_key():
    """Test deriving attachments from security-key hint."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["security-key"])
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_hybrid():
    """Test deriving attachments from hybrid hint."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["hybrid"])
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_client_device():
    """Test deriving attachments from client-device hint."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["client-device"])
    assert result == ["platform"]


def test_derive_allowed_attachments_from_hints_multiple():
    """Test deriving attachments from multiple hints."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["security-key", "client-device"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_duplicates():
    """Test that duplicate hints don't create duplicate attachments."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["security-key", "hybrid", "security-key"]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_case_insensitive():
    """Test that hints are case-insensitive."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["Security-Key", "CLIENT-DEVICE"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_with_whitespace():
    """Test that hints with whitespace are handled."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["  security-key  ", "client-device"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_unknown():
    """Test that unknown hints are ignored."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["unknown-hint", "security-key"]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_non_strings():
    """Test that non-string hints are ignored."""
    from server.app import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        [None, 123, "security-key", []]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_empty():
    """Test deriving attachments from empty hints."""
    from server.app import attachments
    
    assert attachments.derive_allowed_attachments_from_hints([]) == []
    assert attachments.derive_allowed_attachments_from_hints(None) == []


def test_normalize_attachment_list_from_list():
    """Test normalizing a list of attachments."""
    from server.app import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", "cross-platform", "Platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_normalize_attachment_list_from_mapping():
    """Test normalizing attachments from a mapping."""
    from server.app import attachments
    
    result = attachments.normalize_attachment_list(
        {"key1": "platform", "key2": "cross-platform"}
    )
    assert set(result) == {"platform", "cross-platform"}


def test_normalize_attachment_list_from_string():
    """Test that strings return empty list."""
    from server.app import attachments
    
    assert attachments.normalize_attachment_list("platform") == []
    assert attachments.normalize_attachment_list("") == []


def test_normalize_attachment_list_from_none():
    """Test that None returns empty list."""
    from server.app import attachments
    
    assert attachments.normalize_attachment_list(None) == []


def test_normalize_attachment_list_from_bytes():
    """Test that bytes return empty list."""
    from server.app import attachments
    
    assert attachments.normalize_attachment_list(b"platform") == []


def test_normalize_attachment_list_from_non_iterable_value():
    """Test that non-iterable values are rejected."""
    from server.app import attachments

    assert attachments.normalize_attachment_list(12345) == []


def test_normalize_attachment_list_removes_duplicates():
    """Test that duplicates are removed."""
    from server.app import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", "platform", "cross-platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_normalize_attachment_list_filters_invalid():
    """Test that invalid values are filtered out."""
    from server.app import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", None, 123, "", "cross-platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_resolve_effective_attachments_from_hints():
    """Test resolving attachments when hints are provided."""
    from server.app import attachments
    
    result = attachments.resolve_effective_attachments(["security-key"])
    assert result == ["cross-platform"]


def test_resolve_effective_attachments_from_requested():
    """Test resolving attachments from requested attachment when no hints."""
    from server.app import attachments
    
    result = attachments.resolve_effective_attachments([], "platform")
    assert result == ["platform"]


def test_resolve_effective_attachments_hints_take_priority():
    """Test that hints take priority over requested attachment."""
    from server.app import attachments
    
    result = attachments.resolve_effective_attachments(
        ["security-key"], "platform"
    )
    assert result == ["cross-platform"]


def test_resolve_effective_attachments_empty():
    """Test resolving attachments when nothing is provided."""
    from server.app import attachments
    
    result = attachments.resolve_effective_attachments([])
    assert result == []
    
    result = attachments.resolve_effective_attachments([], None)
    assert result == []


def test_build_credential_attachment_map(monkeypatch):
    """Test building credential attachment map."""
    from server.app import attachments
    
    # Mock the ensure_metadata_session_id in attachments module
    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")
    
    # Mock credentials with various formats
    test_credentials = [
        (
            "user1@example.com",
            [
                {
                    "credential_id": b"cred-1",
                    "authenticator_attachment": "platform",
                }
            ]
        ),
        (
            "user2@example.com",
            [
                {
                    "credential_id": b"cred-2",
                    "authenticatorAttachment": "cross-platform",
                }
            ]
        ),
        (
            "user3@example.com",
            [
                {
                    "credential_id": b"cred-3",
                    "properties": {
                        "authenticatorAttachment": "platform"
                    }
                }
            ]
        ),
    ]
    
    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    
    # Mock extract_credential_data to return the credential itself
    monkeypatch.setattr(attachments, "extract_credential_data", lambda cred: cred)
    
    result = attachments.build_credential_attachment_map()
    
    assert result[b"cred-1"] == "platform"
    assert result[b"cred-2"] == "cross-platform"
    assert result[b"cred-3"] == "platform"


def test_build_credential_attachment_map_with_objects(monkeypatch):
    """Test building attachment map with object-style credentials."""
    from server.app import attachments
    
    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")
    
    # Create mock credential object
    class CredData:
        def __init__(self, cred_id):
            self.credential_id = cred_id
    
    test_credentials = [
        (
            "user@example.com",
            [
                {
                    "credential_id": b"cred-obj",
                    "authenticator_attachment": "platform"
                }
            ]
        )
    ]
    
    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    
    # Return object-style data
    monkeypatch.setattr(attachments, "extract_credential_data", lambda cred: CredData(b"cred-obj"))
    
    result = attachments.build_credential_attachment_map()
    
    # Object has credential_id but no attachment, so it should be None
    assert b"cred-obj" in result


def test_build_credential_attachment_map_no_attachment(monkeypatch):
    """Test building map with credentials that have no attachment info."""
    from server.app import attachments
    
    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")
    
    test_credentials = [
        (
            "user@example.com",
            [
                {
                    "credential_id": b"cred-no-attach",
                }
            ]
        )
    ]
    
    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    monkeypatch.setattr(attachments, "extract_credential_data", lambda cred: cred)
    
    result = attachments.build_credential_attachment_map()
    
    assert result[b"cred-no-attach"] is None


def test_build_credential_attachment_map_invalid_credential_id(monkeypatch):
    """Test that credentials with invalid ID are skipped."""
    from server.app import attachments
    
    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")
    
    test_credentials = [
        (
            "user@example.com",
            [
                {
                    "credential_id": "not-bytes",  # Invalid
                    "authenticator_attachment": "platform",
                },
                {
                    "credential_id": b"valid-cred",
                    "authenticator_attachment": "cross-platform",
                }
            ]
        )
    ]
    
    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    monkeypatch.setattr(attachments, "extract_credential_data", lambda cred: cred)
    
    result = attachments.build_credential_attachment_map()
    
    # Invalid ID should be skipped
    assert b"valid-cred" in result
    assert len(result) == 1


def test_build_credential_attachment_map_memoryview(monkeypatch):
    """Test that memoryview credential IDs are handled."""
    from server.app import attachments
    
    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")
    
    test_credentials = [
        (
            "user@example.com",
            [
                {
                    "credential_id": memoryview(b"cred-mem"),
                    "authenticator_attachment": "platform",
                }
            ]
        )
    ]
    
    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    monkeypatch.setattr(attachments, "extract_credential_data", lambda cred: cred)
    
    result = attachments.build_credential_attachment_map()
    
    assert b"cred-mem" in result
    assert result[b"cred-mem"] == "platform"


def test_build_credential_attachment_map_skips_invalid_object_credential_ids(monkeypatch):
    """Test object-backed credentials with invalid IDs are skipped safely."""
    from server.app import attachments

    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")

    class _CredData:
        def __init__(self, credential_id):
            self.credential_id = credential_id

    bad_cred = object()
    good_cred = object()
    test_credentials = [("user@example.com", [bad_cred, good_cred])]

    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    monkeypatch.setattr(
        attachments,
        "extract_credential_data",
        lambda cred: _CredData("not-bytes") if cred is bad_cred else _CredData(b"cred-good"),
    )

    result = attachments.build_credential_attachment_map()

    assert result == {b"cred-good": None}


def test_build_credential_attachment_map_handles_non_mapping_credentials(monkeypatch):
    """Test non-mapping credential containers still produce attachment entries."""
    from server.app import attachments

    monkeypatch.setattr(attachments, "ensure_metadata_session_id", lambda: "test-session")

    class _CredData:
        credential_id = b"cred-object"

    class _CredentialObject:
        pass

    test_credentials = [("user@example.com", [_CredentialObject()])]

    monkeypatch.setattr(attachments, "iter_credentials", lambda **kwargs: iter(test_credentials))
    monkeypatch.setattr(attachments, "extract_credential_data", lambda _cred: _CredData())

    result = attachments.build_credential_attachment_map()

    assert result == {b"cred-object": None}
