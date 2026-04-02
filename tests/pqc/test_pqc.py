"""Tests for the PQC algorithm integration module."""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest


def _setup_oqs_mock(enabled_mechanisms=None):
    """Create a mock oqs module for testing."""
    if enabled_mechanisms is None:
        enabled_mechanisms = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    
    oqs_mock = types.ModuleType("oqs")
    oqs_mock.get_enabled_sig_mechanisms = lambda: enabled_mechanisms
    
    # Add a Signature class for older compatibility
    signature_class = type("Signature", (), {"algorithms": enabled_mechanisms})
    oqs_mock.Signature = signature_class
    
    sys.modules["oqs"] = oqs_mock
    return oqs_mock


def _remove_oqs_mock():
    """Remove the oqs mock from sys.modules."""
    if "oqs" in sys.modules:
        del sys.modules["oqs"]


@pytest.fixture(autouse=True)
def _reload_pqc():
    """Reload pqc module after each test to get fresh state."""
    yield
    _remove_oqs_mock()
    # Force reload if module was already imported
    if "server.app.pqc" in sys.modules:
        importlib.reload(sys.modules["server.app.pqc"])


def test_pqc_algorithm_id_to_name_mapping():
    """Test that PQC algorithm constants are correctly defined."""
    from server.app import pqc
    
    assert pqc.PQC_ALGORITHM_ID_TO_NAME == {
        -50: "ML-DSA-87",
        -49: "ML-DSA-65",
        -48: "ML-DSA-44",
    }


def test_is_pqc_algorithm_recognizes_pqc():
    """Test that PQC algorithms are correctly identified."""
    from server.app import pqc
    
    assert pqc.is_pqc_algorithm(-48) is True
    assert pqc.is_pqc_algorithm(-49) is True
    assert pqc.is_pqc_algorithm(-50) is True


def test_is_pqc_algorithm_rejects_non_pqc():
    """Test that non-PQC algorithms are correctly rejected."""
    from server.app import pqc
    
    assert pqc.is_pqc_algorithm(-7) is False
    assert pqc.is_pqc_algorithm(-8) is False
    assert pqc.is_pqc_algorithm(-257) is False


def test_describe_algorithm_for_pqc():
    """Test algorithm description for PQC algorithms."""
    from server.app import pqc
    
    assert pqc.describe_algorithm(-48) == "ML-DSA-44 (PQC)"
    assert pqc.describe_algorithm(-49) == "ML-DSA-65 (PQC)"
    assert pqc.describe_algorithm(-50) == "ML-DSA-87 (PQC)"


def test_describe_algorithm_for_eddsa():
    """Test algorithm description for EdDSA variants."""
    from server.app import pqc
    
    assert pqc.describe_algorithm(-8) == "EdDSA"
    assert pqc.describe_algorithm(-19) == "Ed25519"
    assert pqc.describe_algorithm(-53) == "Ed448"


def test_describe_algorithm_for_ecdsa():
    """Test algorithm description for ECDSA variants."""
    from server.app import pqc
    
    assert pqc.describe_algorithm(-7) == "ES256 (ECDSA)"
    assert pqc.describe_algorithm(-9) == "ESP256 (ECDSA)"
    assert pqc.describe_algorithm(-47) == "ES256K (ECDSA)"
    assert pqc.describe_algorithm(-35) == "ES384 (ECDSA)"
    assert pqc.describe_algorithm(-36) == "ES512 (ECDSA)"
    assert pqc.describe_algorithm(-51) == "ESP384 (ECDSA)"
    assert pqc.describe_algorithm(-52) == "ESP512 (ECDSA)"


def test_describe_algorithm_for_rsa():
    """Test algorithm description for RSA variants."""
    from server.app import pqc
    
    assert pqc.describe_algorithm(-37) == "PS256 (RSA-PSS)"
    assert pqc.describe_algorithm(-38) == "PS384 (RSA-PSS)"
    assert pqc.describe_algorithm(-39) == "PS512 (RSA-PSS)"
    assert pqc.describe_algorithm(-257) == "RS256 (RSA)"
    assert pqc.describe_algorithm(-258) == "RS384 (RSA)"
    assert pqc.describe_algorithm(-259) == "RS512 (RSA)"
    assert pqc.describe_algorithm(-65535) == "RS1 (RSA)"


def test_describe_algorithm_for_unknown():
    """Test algorithm description for unknown algorithms."""
    from server.app import pqc
    
    assert pqc.describe_algorithm(None) == "Unknown"
    assert pqc.describe_algorithm(-999) == "COSE alg -999"
    assert pqc.describe_algorithm(123) == "COSE alg 123"


def test_detect_available_pqc_algorithms_all_available(monkeypatch):
    """Test detection when all PQC algorithms are available."""
    _setup_oqs_mock(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Other-Algo"])
    
    from server.app import pqc
    
    available, error = pqc.detect_available_pqc_algorithms()
    
    assert available == {-48, -49, -50}
    assert error is None


def test_detect_available_pqc_algorithms_partial_available(monkeypatch):
    """Test detection when only some PQC algorithms are available."""
    _setup_oqs_mock(["ML-DSA-44", "ML-DSA-65"])
    
    from server.app import pqc
    
    available, error = pqc.detect_available_pqc_algorithms()
    
    assert available == {-48, -49}
    assert error is not None
    assert "ML-DSA-87" in error


def test_detect_available_pqc_algorithms_none_available(monkeypatch):
    """Test detection when no PQC algorithms are available."""
    _setup_oqs_mock([])
    
    from server.app import pqc
    
    available, error = pqc.detect_available_pqc_algorithms()
    
    assert available == set()
    assert error is not None
    assert "ML-DSA-44" in error
    assert "ML-DSA-65" in error
    assert "ML-DSA-87" in error


def test_detect_available_pqc_algorithms_import_error():
    """Test detection when oqs is not available."""
    _remove_oqs_mock()
    
    from server.app import pqc
    
    available, error = pqc.detect_available_pqc_algorithms()
    
    assert available == set()
    assert error is not None
    assert "oqs" in error.lower()
    assert "liboqs" in error.lower()


def test_load_enabled_mechanisms_with_get_enabled_sig_mechanisms():
    """Test loading mechanisms using the modern API."""
    _setup_oqs_mock(["ML-DSA-44", "ML-DSA-65"])
    
    from server.app import pqc
    
    mechanisms = list(pqc._load_enabled_mechanisms())
    assert mechanisms == ["ML-DSA-44", "ML-DSA-65"]


def test_log_algorithm_selection_with_none(monkeypatch):
    """Test logging when no algorithm is selected."""
    from server.app import pqc
    from server.app.config import app
    
    logged = []
    monkeypatch.setattr(app.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("registration", None)
    
    assert len(logged) == 1
    assert "No signature algorithm" in logged[0][0]
    assert logged[0][1] == ("registration",)


def test_log_algorithm_selection_with_pqc(monkeypatch):
    """Test logging when a PQC algorithm is selected."""
    from server.app import pqc
    from server.app.config import app
    
    logged = []
    monkeypatch.setattr(app.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("authentication", -48)
    
    assert len(logged) == 1
    assert "post-quantum algorithm" in logged[0][0]
    assert logged[0][1] == ("ML-DSA-44 (PQC)", -48, "authentication")


def test_log_algorithm_selection_with_classical(monkeypatch):
    """Test logging when a classical algorithm is selected."""
    from server.app import pqc
    from server.app.config import app
    
    logged = []
    monkeypatch.setattr(app.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("registration", -7)
    
    assert len(logged) == 1
    assert "classical algorithm" in logged[0][0]
    assert logged[0][1] == ("ES256 (ECDSA)", -7, "registration")
