"""Tests for the PQC algorithm integration module."""

from __future__ import annotations

from server.app.routes.advanced import algorithms
from server.app.webauthn import pqc


def test_is_pqc_algorithm_recognizes_pqc():
    """Test that PQC algorithms are correctly identified."""
    
    assert pqc.is_pqc_algorithm(-48) is True
    assert pqc.is_pqc_algorithm(-49) is True
    assert pqc.is_pqc_algorithm(-50) is True


def test_is_pqc_algorithm_rejects_non_pqc():
    """Test that non-PQC algorithms are correctly rejected."""
    
    assert pqc.is_pqc_algorithm(-7) is False
    assert pqc.is_pqc_algorithm(-8) is False
    assert pqc.is_pqc_algorithm(-257) is False


def test_describe_algorithm_for_pqc():
    """Test algorithm description for PQC algorithms."""
    
    assert pqc.describe_algorithm(-48) == "ML-DSA-44 (PQC)"
    assert pqc.describe_algorithm(-49) == "ML-DSA-65 (PQC)"
    assert pqc.describe_algorithm(-50) == "ML-DSA-87 (PQC)"


def test_describe_algorithm_for_eddsa():
    """Test algorithm description for EdDSA variants."""
    
    assert pqc.describe_algorithm(-8) == "EdDSA"
    assert pqc.describe_algorithm(-19) == "Ed25519"
    assert pqc.describe_algorithm(-53) == "Ed448"


def test_describe_algorithm_for_ecdsa():
    """Test algorithm description for ECDSA variants."""
    
    assert pqc.describe_algorithm(-7) == "ES256 (ECDSA)"
    assert pqc.describe_algorithm(-9) == "ESP256 (ECDSA)"
    assert pqc.describe_algorithm(-47) == "ES256K (ECDSA)"
    assert pqc.describe_algorithm(-35) == "ES384 (ECDSA)"
    assert pqc.describe_algorithm(-36) == "ES512 (ECDSA)"
    assert pqc.describe_algorithm(-51) == "ESP384 (ECDSA)"
    assert pqc.describe_algorithm(-52) == "ESP512 (ECDSA)"


def test_describe_algorithm_for_rsa():
    """Test algorithm description for RSA variants."""
    
    assert pqc.describe_algorithm(-37) == "PS256 (RSA-PSS)"
    assert pqc.describe_algorithm(-38) == "PS384 (RSA-PSS)"
    assert pqc.describe_algorithm(-39) == "PS512 (RSA-PSS)"
    assert pqc.describe_algorithm(-257) == "RS256 (RSA)"
    assert pqc.describe_algorithm(-258) == "RS384 (RSA)"
    assert pqc.describe_algorithm(-259) == "RS512 (RSA)"
    assert pqc.describe_algorithm(-65535) == "RS1 (RSA)"


def test_describe_algorithm_for_unknown():
    """Test algorithm description for unknown algorithms."""
    
    assert pqc.describe_algorithm(None) == "Unknown"
    assert pqc.describe_algorithm(-999) == "COSE alg -999"
    assert pqc.describe_algorithm(123) == "COSE alg 123"


def test_log_algorithm_selection_with_none(monkeypatch):
    """Test logging when no algorithm is selected."""
    
    logged = []
    monkeypatch.setattr(pqc.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("registration", None)
    
    assert len(logged) == 1
    assert "No signature algorithm" in logged[0][0]
    assert logged[0][1] == ("registration",)


def test_log_algorithm_selection_with_pqc(monkeypatch):
    """Test logging when a PQC algorithm is selected."""
    
    logged = []
    monkeypatch.setattr(pqc.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("authentication", -48)
    
    assert len(logged) == 1
    assert "post-quantum algorithm" in logged[0][0]
    assert logged[0][1] == ("ML-DSA-44 (PQC)", -48, "authentication")


def test_log_algorithm_selection_with_classical(monkeypatch):
    """Test logging when a classical algorithm is selected."""
    
    logged = []
    monkeypatch.setattr(pqc.logger, "info", lambda msg, *args: logged.append((msg, args)))
    
    pqc.log_algorithm_selection("registration", -7)
    
    assert len(logged) == 1
    assert "classical algorithm" in logged[0][0]
    assert logged[0][1] == ("ES256 (ECDSA)", -7, "registration")


def test_fido2_verifies_every_mldsa_parameter_set_in_this_build():
    assert {-48, -49, -50} <= algorithms._verifiable_algorithms()
