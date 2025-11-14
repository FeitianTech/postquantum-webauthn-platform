"""Tests for the fido2 payment module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from fido2.payment import (
    CollectedClientAdditionalPaymentData,
    PaymentClientDataCollector,
)
from fido2.ctap2.extensions import (
    PaymentCredentialInstrument,
    PaymentCurrencyAmount,
)
from fido2.webauthn import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def test_collected_client_additional_payment_data_creation():
    """Test creating CollectedClientAdditionalPaymentData."""
    total = PaymentCurrencyAmount(currency="USD", value="10.00")
    instrument = PaymentCredentialInstrument(
        display_name="Test Card",
        icon="https://example.com/icon.png"
    )
    
    data = CollectedClientAdditionalPaymentData(
        rp_id="example.com",
        top_origin="https://example.com",
        payee_name="Test Payee",
        payee_origin="https://payee.example.com",
        total=total,
        instrument=instrument
    )
    
    assert data.rp_id == "example.com"
    assert data.top_origin == "https://example.com"
    assert data.payee_name == "Test Payee"
    assert data.payee_origin == "https://payee.example.com"
    assert data.total == total
    assert data.instrument == instrument


def test_collected_client_additional_payment_data_optional_fields():
    """Test creating CollectedClientAdditionalPaymentData with optional fields omitted."""
    total = PaymentCurrencyAmount(currency="USD", value="10.00")
    instrument = PaymentCredentialInstrument(
        display_name="Test Card",
        icon="https://example.com/icon.png"
    )
    
    data = CollectedClientAdditionalPaymentData(
        rp_id="example.com",
        top_origin="https://example.com",
        total=total,
        instrument=instrument
    )
    
    assert data.payee_name is None
    assert data.payee_origin is None


def test_payment_client_data_collector_init():
    """Test initializing PaymentClientDataCollector."""
    collector = PaymentClientDataCollector("https://example.com")
    assert collector._origin == "https://example.com"


def test_payment_client_data_collector_collect_without_payment():
    """Test collecting client data without payment extension."""
    collector = PaymentClientDataCollector("https://example.com")
    
    options = PublicKeyCredentialRequestOptions(
        challenge=b"test-challenge",
        rp_id="example.com"
    )
    
    client_data, rp_id = collector.collect_client_data(options)
    
    assert client_data.type == "webauthn.get"
    assert rp_id == "example.com"


def test_payment_client_data_collector_creation_options_invalid():
    """Test that creation options with payment must have correct authenticator selection."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    # Missing authenticator selection
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        extensions={"payment": payment_inputs}
    )
    
    with pytest.raises(ValueError, match="Invalid options for payment extension"):
        collector.collect_client_data(options)


def test_payment_client_data_collector_creation_options_valid_platform():
    """Test that creation options with payment work with platform attachment."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    # Valid authenticator selection
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        extensions={"payment": payment_inputs}
    )
    
    # This should not raise - will fall through to default behavior
    client_data, rp_id = collector.collect_client_data(options)
    assert client_data.type == "webauthn.create"


def test_payment_client_data_collector_creation_options_valid_cross_platform():
    """Test that creation options work with cross-platform (against spec but allowed)."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        extensions={"payment": payment_inputs}
    )
    
    client_data, rp_id = collector.collect_client_data(options)
    assert client_data.type == "webauthn.create"


def test_payment_client_data_collector_creation_options_invalid_resident_key():
    """Test that creation options with wrong resident key requirement fail."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,  # Wrong!
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        extensions={"payment": payment_inputs}
    )
    
    with pytest.raises(ValueError, match="Invalid options for payment extension"):
        collector.collect_client_data(options)


def test_payment_client_data_collector_creation_options_preferred_resident_key():
    """Test that creation options with preferred resident key work."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,  # Also valid
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        extensions={"payment": payment_inputs}
    )
    
    client_data, rp_id = collector.collect_client_data(options)
    assert client_data.type == "webauthn.create"


def test_payment_client_data_collector_creation_options_invalid_user_verification():
    """Test that creation options with wrong user verification fail."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": True,
        "rpId": "example.com",
        "topOrigin": "https://example.com",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Test Card",
            "icon": "https://example.com/icon.png"
        }
    }
    
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
        user=PublicKeyCredentialUserEntity(
            id=b"user-id",
            name="test@example.com",
            display_name="Test User"
        ),
        challenge=b"test-challenge",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.DISCOURAGED  # Wrong!
        ),
        extensions={"payment": payment_inputs}
    )
    
    with pytest.raises(ValueError, match="Invalid options for payment extension"):
        collector.collect_client_data(options)


def test_payment_client_data_collector_non_payment():
    """Test that non-payment extensions pass through normally."""
    collector = PaymentClientDataCollector("https://example.com")
    
    payment_inputs = {
        "isPayment": False,  # Not a payment
        "rpId": "example.com"
    }
    
    options = PublicKeyCredentialRequestOptions(
        challenge=b"test-challenge",
        rp_id="example.com",
        extensions={"payment": payment_inputs}
    )
    
    client_data, rp_id = collector.collect_client_data(options)
    assert client_data.type == "webauthn.get"

