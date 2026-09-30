"""Tests for authenticator attachment helpers."""

from __future__ import annotations


def test_hint_to_attachment_map():
    """Test that the hint-to-attachment mapping is correctly defined."""
    from server.app.webauthn import attachments
    
    assert attachments.HINT_TO_ATTACHMENT_MAP == {
        "security-key": "cross-platform",
        "hybrid": "cross-platform",
        "client-device": "platform",
    }


def test_normalize_attachment_with_string():
    """Test normalizing valid attachment strings."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment("platform") == "platform"
    assert attachments.normalize_attachment("cross-platform") == "cross-platform"
    assert attachments.normalize_attachment("  Platform  ") == "platform"
    assert attachments.normalize_attachment("CROSS-PLATFORM") == "cross-platform"


def test_normalize_attachment_with_empty():
    """Test normalizing empty or whitespace-only strings."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment("") is None
    assert attachments.normalize_attachment("   ") is None


def test_normalize_attachment_with_non_string():
    """Test normalizing non-string values."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment(None) is None
    assert attachments.normalize_attachment(123) is None
    assert attachments.normalize_attachment([]) is None
    assert attachments.normalize_attachment({}) is None


def test_derive_allowed_attachments_from_hints_security_key():
    """Test deriving attachments from security-key hint."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["security-key"])
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_hybrid():
    """Test deriving attachments from hybrid hint."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["hybrid"])
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_client_device():
    """Test deriving attachments from client-device hint."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(["client-device"])
    assert result == ["platform"]


def test_derive_allowed_attachments_from_hints_multiple():
    """Test deriving attachments from multiple hints."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["security-key", "client-device"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_duplicates():
    """Test that duplicate hints don't create duplicate attachments."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["security-key", "hybrid", "security-key"]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_case_insensitive():
    """Test that hints are case-insensitive."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["Security-Key", "CLIENT-DEVICE"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_with_whitespace():
    """Test that hints with whitespace are handled."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["  security-key  ", "client-device"]
    )
    assert result == ["cross-platform", "platform"]


def test_derive_allowed_attachments_from_hints_unknown():
    """Test that unknown hints are ignored."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        ["unknown-hint", "security-key"]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_non_strings():
    """Test that non-string hints are ignored."""
    from server.app.webauthn import attachments
    
    result = attachments.derive_allowed_attachments_from_hints(
        [None, 123, "security-key", []]
    )
    assert result == ["cross-platform"]


def test_derive_allowed_attachments_from_hints_empty():
    """Test deriving attachments from empty hints."""
    from server.app.webauthn import attachments
    
    assert attachments.derive_allowed_attachments_from_hints([]) == []
    assert attachments.derive_allowed_attachments_from_hints(None) == []


def test_normalize_attachment_list_from_list():
    """Test normalizing a list of attachments."""
    from server.app.webauthn import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", "cross-platform", "Platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_normalize_attachment_list_from_mapping():
    """Test normalizing attachments from a mapping."""
    from server.app.webauthn import attachments
    
    result = attachments.normalize_attachment_list(
        {"key1": "platform", "key2": "cross-platform"}
    )
    assert set(result) == {"platform", "cross-platform"}


def test_normalize_attachment_list_from_string():
    """Test that strings return empty list."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment_list("platform") == []
    assert attachments.normalize_attachment_list("") == []


def test_normalize_attachment_list_from_none():
    """Test that None returns empty list."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment_list(None) == []


def test_normalize_attachment_list_from_bytes():
    """Test that bytes return empty list."""
    from server.app.webauthn import attachments
    
    assert attachments.normalize_attachment_list(b"platform") == []


def test_normalize_attachment_list_from_non_iterable_value():
    """Test that non-iterable values are rejected."""
    from server.app.webauthn import attachments

    assert attachments.normalize_attachment_list(12345) == []


def test_normalize_attachment_list_removes_duplicates():
    """Test that duplicates are removed."""
    from server.app.webauthn import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", "platform", "cross-platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_normalize_attachment_list_filters_invalid():
    """Test that invalid values are filtered out."""
    from server.app.webauthn import attachments
    
    result = attachments.normalize_attachment_list(
        ["platform", None, 123, "", "cross-platform"]
    )
    assert result == ["platform", "cross-platform"]


def test_resolve_effective_attachments_from_hints():
    """Test resolving attachments when hints are provided."""
    from server.app.webauthn import attachments
    
    result = attachments.resolve_effective_attachments(["security-key"])
    assert result == ["cross-platform"]


def test_resolve_effective_attachments_from_requested():
    """Test resolving attachments from requested attachment when no hints."""
    from server.app.webauthn import attachments
    
    result = attachments.resolve_effective_attachments([], "platform")
    assert result == ["platform"]


def test_resolve_effective_attachments_hints_take_priority():
    """Test that hints take priority over requested attachment."""
    from server.app.webauthn import attachments
    
    result = attachments.resolve_effective_attachments(
        ["security-key"], "platform"
    )
    assert result == ["cross-platform"]


def test_resolve_effective_attachments_empty():
    """Test resolving attachments when nothing is provided."""
    from server.app.webauthn import attachments
    
    result = attachments.resolve_effective_attachments([])
    assert result == []
    
    result = attachments.resolve_effective_attachments([], None)
    assert result == []
