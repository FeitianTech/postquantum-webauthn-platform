"""Tests for the fido2 payment module."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from fido2.payment import (
    CollectedClientAdditionalPaymentData,
    CollectedClientPaymentData,
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


def test_payment_client_data_collector_request_options_payment_get_flow():
    """Document current payment.get failure mode for request options."""
    collector = PaymentClientDataCollector("https://example.com")

    payment_inputs = {
        "isPayment": True,
        "rpId": "merchant.example",
        "topOrigin": "https://shop.example",
        "payeeName": "Example Store",
        "payeeOrigin": "https://shop.example",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Visa **** 0001",
            "icon": "https://example.com/card.png",
        },
    }

    options = PublicKeyCredentialRequestOptions(
        challenge=b"test-challenge",
        rp_id="merchant.example",
        extensions={"payment": payment_inputs},
    )

    with pytest.raises(AttributeError, match="_data"):
        collector.collect_client_data(options)


def test_collected_client_payment_data_create_maps_payment_payload_when_base_sets_data(monkeypatch):
    """Exercise CollectedClientPaymentData.create/__init__ mapping logic."""
    import fido2.payment as payment_module

    def _fake_base_init(self, serialized: bytes):
        payload = json.loads(serialized.decode("utf-8"))
        object.__setattr__(self, "_data", payload)
        object.__setattr__(self, "type", payload["type"])
        object.__setattr__(self, "challenge", payload["challenge"])
        object.__setattr__(self, "origin", payload["origin"])
        object.__setattr__(self, "cross_origin", payload.get("crossOrigin", False))

    monkeypatch.setattr(payment_module.CollectedClientData, "__init__", _fake_base_init)
    monkeypatch.setattr(
        payment_module.CollectedClientAdditionalPaymentData,
        "from_dict",
        classmethod(lambda _cls, data: SimpleNamespace(mapped=data)),
    )

    result = payment_module.CollectedClientPaymentData.create(
        type="payment.get",
        challenge="challenge-token",
        origin="https://example.com",
        payment={"marker": "ok"},
    )

    assert isinstance(result, CollectedClientPaymentData)
    assert result.payment.mapped == {"marker": "ok"}


def test_payment_client_data_collector_request_options_payment_branch_returns_tuple(monkeypatch):
    """Ensure request-option payment branch returns patched payment client data tuple."""
    collector = PaymentClientDataCollector("https://example.com")

    payment_inputs = {
        "isPayment": True,
        "rpId": "merchant.example",
        "topOrigin": "https://shop.example",
        "total": {"currency": "USD", "value": "10.00"},
        "instrument": {
            "displayName": "Visa **** 0001",
            "icon": "https://example.com/card.png",
        },
    }

    options = PublicKeyCredentialRequestOptions(
        challenge=b"test-challenge",
        rp_id="merchant.example",
        extensions={"payment": payment_inputs},
    )

    marker = object()
    monkeypatch.setattr(
        CollectedClientPaymentData,
        "create",
        classmethod(lambda _cls, **_kwargs: marker),
    )

    client_data, rp_id = collector.collect_client_data(options)

    assert client_data is marker
    assert rp_id == "merchant.example"


def test_payment_client_data_collector_payment_inputs_unknown_options_fall_back(monkeypatch):
    """Payment inputs on unknown option types should fall back to default collection."""
    import fido2.payment as payment_module

    collector = PaymentClientDataCollector("https://example.com")

    class UnknownOptions:
        extensions = {
            "payment": {
                "isPayment": True,
                "rpId": "merchant.example",
                "topOrigin": "https://shop.example",
                "total": {"currency": "USD", "value": "10.00"},
                "instrument": {
                    "displayName": "Visa **** 0001",
                    "icon": "https://example.com/card.png",
                },
            }
        }

    options = UnknownOptions()
    verify_calls = []

    monkeypatch.setattr(collector, "get_rp_id", lambda _options, _origin: "merchant.example")
    monkeypatch.setattr(
        collector,
        "verify_rp_id",
        lambda rp_id, origin: verify_calls.append((rp_id, origin)),
    )
    monkeypatch.setattr(
        payment_module.DefaultClientDataCollector,
        "collect_client_data",
        lambda _self, _options: ("fallback-client-data", "merchant.example"),
    )

    client_data, rp_id = collector.collect_client_data(options)

    assert client_data == "fallback-client-data"
    assert rp_id == "merchant.example"
    assert verify_calls == [("merchant.example", "https://example.com")]

