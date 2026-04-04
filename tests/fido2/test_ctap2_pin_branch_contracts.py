from __future__ import annotations

import os
import types

import pytest

from fido2.utils import hmac_sha256
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2, _pad_pin


class _DummyProtocol:
    VERSION = 9

    def encapsulate(self, peer_cose_key):
        return {1: "key"}, b"shared"

    def encrypt(self, key, plaintext):
        return b"enc:" + plaintext

    def decrypt(self, key, ciphertext):
        assert ciphertext.startswith(b"enc:")
        return ciphertext[4:]

    def authenticate(self, key, message):
        return b"auth-tag"

    def validate_token(self, token):
        return b"validated:" + token


class _FakeCtap:
    def __init__(self, *, options=None, pin_uv_protocols=None):
        self.info = types.SimpleNamespace(
            options=options or {},
            pin_uv_protocols=pin_uv_protocols or [],
        )
        self.calls = []
        self.responses = {}

    def client_pin(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        command = args[1]
        return self.responses.get(command, {})


def test_pad_pin_and_protocol_token_validation_edges():
    with pytest.raises(ValueError, match="wrong type"):
        _pad_pin(1234)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=">= 4"):
        _pad_pin("123")

    with pytest.raises(ValueError, match="<= 255"):
        _pad_pin("x" * 256)

    padded = _pad_pin("1234")
    assert padded.startswith(b"1234")
    assert len(padded) % 16 == 0

    with pytest.raises(ValueError, match="16 or 32"):
        PinProtocolV1().validate_token(b"short")


def test_pin_protocol_v2_encrypt_decrypt_and_authenticate(monkeypatch):
    protocol = PinProtocolV2()

    fixed_iv = b"\x11" * 16
    monkeypatch.setattr(os, "urandom", lambda size: fixed_iv)

    key = protocol.kdf(b"shared-secret")
    plaintext = b"0123456789abcdef"

    encrypted = protocol.encrypt(key, plaintext)
    assert encrypted[:16] == fixed_iv
    assert protocol.decrypt(key, encrypted) == plaintext

    message = b"pin-protocol-v2-message"
    assert protocol.authenticate(key, message) == hmac_sha256(key[:32], message)

    token = b"T" * 32
    assert protocol.validate_token(token) == token

    with pytest.raises(ValueError, match="32 bytes"):
        protocol.validate_token(b"T" * 16)


def test_client_pin_protocol_selection_and_error_paths():
    selected_v1 = ClientPin(_FakeCtap(pin_uv_protocols=[1]))
    assert isinstance(selected_v1.protocol, PinProtocolV1)

    selected_v2 = ClientPin(_FakeCtap(pin_uv_protocols=[2]))
    assert isinstance(selected_v2.protocol, PinProtocolV2)

    with pytest.raises(ValueError, match="No compatible PIN/UV protocols"):
        ClientPin(_FakeCtap(pin_uv_protocols=[99]))


def test_get_pin_token_branches_and_permission_forwarding(monkeypatch):
    modern_ctap = _FakeCtap(
        options={"clientPin": True, "pinUvAuthToken": True},
        pin_uv_protocols=[_DummyProtocol.VERSION],
    )
    modern_ctap.responses[ClientPin.CMD.GET_TOKEN_USING_PIN] = {
        ClientPin.RESULT.PIN_UV_TOKEN: b"enc:modern-token"
    }

    modern_client_pin = ClientPin(modern_ctap, _DummyProtocol())
    monkeypatch.setattr(
        modern_client_pin,
        "_get_shared_secret",
        lambda: ({"k": "v"}, b"shared"),
        raising=False,
    )

    token = modern_client_pin.get_pin_token(
        "1234",
        permissions=ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid="example.com",
    )
    assert token == b"validated:modern-token"

    args, kwargs = modern_ctap.calls[-1]
    assert args[1] == ClientPin.CMD.GET_TOKEN_USING_PIN
    assert kwargs["permissions"] == ClientPin.PERMISSION.GET_ASSERTION
    assert kwargs["permissions_rpid"] == "example.com"

    legacy_ctap = _FakeCtap(
        options={"clientPin": True, "pinUvAuthToken": False},
        pin_uv_protocols=[_DummyProtocol.VERSION],
    )
    legacy_ctap.responses[ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY] = {
        ClientPin.RESULT.PIN_UV_TOKEN: b"enc:legacy-token"
    }

    legacy_client_pin = ClientPin(legacy_ctap, _DummyProtocol())
    monkeypatch.setattr(
        legacy_client_pin,
        "_get_shared_secret",
        lambda: ({"k": "v"}, b"shared"),
        raising=False,
    )

    token_legacy = legacy_client_pin.get_pin_token(
        "1234",
        permissions=ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid="ignored.example",
    )
    assert token_legacy == b"validated:legacy-token"

    legacy_args, legacy_kwargs = legacy_ctap.calls[-1]
    assert legacy_args[1] == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY
    assert legacy_kwargs["permissions"] is None
    assert legacy_kwargs["permissions_rpid"] is None

    unsupported = ClientPin(_FakeCtap(options={}, pin_uv_protocols=[_DummyProtocol.VERSION]), _DummyProtocol())
    with pytest.raises(ValueError, match="does not support get_pin_token"):
        unsupported.get_pin_token("1234")


def test_get_uv_token_and_retry_helpers(monkeypatch):
    ctap = _FakeCtap(
        options={"clientPin": True, "pinUvAuthToken": True},
        pin_uv_protocols=[_DummyProtocol.VERSION],
    )
    ctap.responses[ClientPin.CMD.GET_TOKEN_USING_UV] = {
        ClientPin.RESULT.PIN_UV_TOKEN: b"enc:uv-token"
    }
    ctap.responses[ClientPin.CMD.GET_PIN_RETRIES] = {
        ClientPin.RESULT.PIN_RETRIES: 7,
        ClientPin.RESULT.POWER_CYCLE_STATE: 1,
    }
    ctap.responses[ClientPin.CMD.GET_UV_RETRIES] = {
        ClientPin.RESULT.UV_RETRIES: 3,
    }

    client_pin = ClientPin(ctap, _DummyProtocol())
    monkeypatch.setattr(
        client_pin,
        "_get_shared_secret",
        lambda: ({"k": "v"}, b"shared"),
        raising=False,
    )

    event = object()
    on_keepalive = lambda _status: None
    uv_token = client_pin.get_uv_token(
        permissions=ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid="example.com",
        event=event,
        on_keepalive=on_keepalive,
    )
    assert uv_token == b"validated:uv-token"

    args, kwargs = ctap.calls[0]
    assert args[1] == ClientPin.CMD.GET_TOKEN_USING_UV
    assert kwargs["event"] is event
    assert kwargs["on_keepalive"] is on_keepalive

    assert client_pin.get_pin_retries() == (7, 1)
    assert client_pin.get_uv_retries() == 3

    unsupported_uv = ClientPin(
        _FakeCtap(options={"clientPin": True}, pin_uv_protocols=[_DummyProtocol.VERSION]),
        _DummyProtocol(),
    )
    with pytest.raises(ValueError, match="does not support get_uv_token"):
        unsupported_uv.get_uv_token()


def test_set_pin_and_change_pin_require_client_pin_support():
    unsupported = ClientPin(
        _FakeCtap(options={}, pin_uv_protocols=[_DummyProtocol.VERSION]),
        _DummyProtocol(),
    )
    with pytest.raises(ValueError, match="does not support ClientPin"):
        unsupported.set_pin("1234")

    with pytest.raises(ValueError, match="does not support ClientPin"):
        unsupported.change_pin("1234", "4321")
