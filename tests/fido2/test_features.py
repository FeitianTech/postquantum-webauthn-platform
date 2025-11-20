"""Tests for the fido2 features module."""

from __future__ import annotations

import importlib
import sys
import warnings

import pytest


def test_feature_not_enabled_error():
    """Test that FeatureNotEnabledError is defined."""
    from fido2.features import FeatureNotEnabledError
    
    assert issubclass(FeatureNotEnabledError, Exception)
    
    # Test raising it
    with pytest.raises(FeatureNotEnabledError):
        raise FeatureNotEnabledError("Test error")


def test_feature_enabled_initial_state():
    """Test that feature starts in None state."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    # Initially, the enabled state should be None (unset)
    assert features.webauthn_json_mapping._enabled is None


def test_feature_enabled_getter_shows_warning():
    """Test that accessing enabled property shows deprecation warning."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        _ = features.webauthn_json_mapping.enabled
        
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "webauthn_json_mapping" in str(w[0].message)


def test_feature_enabled_setter_true():
    """Test setting feature to enabled."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = True
    assert features.webauthn_json_mapping.enabled is True


def test_feature_enabled_setter_false():
    """Test setting feature to disabled."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = False
    assert features.webauthn_json_mapping.enabled is False


def test_feature_enabled_setter_cannot_change():
    """Test that feature cannot be reconfigured once set."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = True
    
    with pytest.raises(ValueError, match="has already been configured"):
        features.webauthn_json_mapping.enabled = False


def test_feature_enabled_setter_cannot_change_to_same():
    """Test that feature cannot be reconfigured even to same value."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = True
    
    with pytest.raises(ValueError, match="has already been configured"):
        features.webauthn_json_mapping.enabled = True


def test_feature_require_with_matching_state():
    """Test that require succeeds when state matches."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = True
    
    # Should not raise
    features.webauthn_json_mapping.require(True)


def test_feature_require_with_mismatched_state():
    """Test that require fails when state doesn't match."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = False
    
    with pytest.raises(features.FeatureNotEnabledError, match="requires.*enabled = True"):
        features.webauthn_json_mapping.require(True)


def test_feature_require_with_unset_state():
    """Test that require fails and warns when state is unset."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        
        with pytest.raises(features.FeatureNotEnabledError):
            features.webauthn_json_mapping.require(True)
        
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)


def test_feature_require_false():
    """Test requiring feature to be disabled."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = False
    
    # Should not raise
    features.webauthn_json_mapping.require(False)


def test_feature_warn_when_unset():
    """Test that warn() shows warning when feature is unset."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        features.webauthn_json_mapping.warn()
        
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "webauthn_json_mapping" in str(w[0].message)


def test_feature_warn_when_set_does_not_warn():
    """Test that warn() does not show warning when feature is set."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    features.webauthn_json_mapping.enabled = True
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        features.webauthn_json_mapping.warn()
        
        assert len(w) == 0


def test_feature_name_and_desc():
    """Test that feature has name and description."""
    from fido2 import features
    
    # Reload to get fresh state
    importlib.reload(features)
    
    assert features.webauthn_json_mapping._name == "webauthn_json_mapping"
    assert "JSON values" in features.webauthn_json_mapping._desc
