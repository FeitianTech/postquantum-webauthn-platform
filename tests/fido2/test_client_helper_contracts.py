from __future__ import annotations

from threading import Event
import types

import pytest

import fido2.client as client_mod
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError
from fido2.hid import STATUS
from fido2.webauthn import (
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


def _creation_options(**overrides):
    data = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"u", "name": "user", "displayName": "User"},
        "challenge": b"challenge",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
    data.update(overrides)
    return PublicKeyCredentialCreationOptions.from_dict(data)


def _request_options(**overrides):
    data = {
        "challenge": b"challenge",
        "rpId": "example.com",
        "allowCredentials": [{"type": "public-key", "id": b"cred"}],
    }
    data.update(overrides)
    return PublicKeyCredentialRequestOptions.from_dict(data)


def test_client_error_repr_and_pin_required_defaults():
    err = client_mod.ClientError(client_mod.ClientError.ERR.BAD_REQUEST, "bad")
    assert "BAD_REQUEST" in repr(err)
    assert "cause: bad" in repr(err)

    pin_err = client_mod.PinRequiredError()
    assert pin_err.code == client_mod.ClientError.ERR.BAD_REQUEST
    assert "PIN required" in str(pin_err.cause)


def test_ctap2client_err_mapping_categories():
    pairs = [
        (CtapError.ERR.CREDENTIAL_EXCLUDED, client_mod.ClientError.ERR.DEVICE_INELIGIBLE),
        (CtapError.ERR.ACTION_TIMEOUT, client_mod.ClientError.ERR.TIMEOUT),
        (CtapError.ERR.UNSUPPORTED_OPTION, client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED),
        (CtapError.ERR.INVALID_COMMAND, client_mod.ClientError.ERR.BAD_REQUEST),
        (CtapError.ERR.OTHER, client_mod.ClientError.ERR.OTHER_ERROR),
    ]

    for ctap_code, expected in pairs:
        mapped = client_mod._ctap2client_err(CtapError(ctap_code))
        assert mapped.code == expected


def test_call_polling_success_and_error_paths():
    assert client_mod._call_polling(0.01, Event(), None, lambda: "ok") == "ok"

    # USE_NOT_SATISFIED path with retry.
    calls = {"count": 0}

    def _apdu_retry():
        calls["count"] += 1
        if calls["count"] == 1:
            raise ApduError(APDU.USE_NOT_SATISFIED)
        return "done"

    assert client_mod._call_polling(0.0, Event(), lambda: None, _apdu_retry) == "done"

    with pytest.raises(client_mod.ClientError) as other_err:
        client_mod._call_polling(0.0, Event(), None, lambda: (_ for _ in ()).throw(ApduError(APDU.WRONG_DATA)))
    assert other_err.value.code == client_mod.ClientError.ERR.OTHER_ERROR

    with pytest.raises(client_mod.ClientError) as mapped_err:
        client_mod._call_polling(
            0.0,
            Event(),
            None,
            lambda: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
        )
    assert mapped_err.value.code == client_mod.ClientError.ERR.BAD_REQUEST

    e = Event()
    e.set()
    with pytest.raises(client_mod.ClientError) as timeout_err:
        client_mod._call_polling(0.0, e, None, lambda: "never")
    assert timeout_err.value.code == client_mod.ClientError.ERR.TIMEOUT


def test_assertion_selection_response_and_extension_results(monkeypatch):
    class _FakeAuthenticatorAssertionResponse:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class _FakeAuthenticationResponse:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    monkeypatch.setattr(
        client_mod, "AuthenticatorAssertionResponse", _FakeAuthenticatorAssertionResponse
    )
    monkeypatch.setattr(client_mod, "AuthenticationResponse", _FakeAuthenticationResponse)

    client_data = CollectedClientData.create(
        type=CollectedClientData.TYPE.GET,
        origin="https://example.com",
        challenge=b"challenge",
    )
    assertion = types.SimpleNamespace(
        credential={"id": b"cred"},
        auth_data=b"auth",
        signature=b"sig",
        user={"id": b"user"},
    )

    sel = client_mod.AssertionSelection(client_data, [assertion], {"ext": True})
    assert sel.get_assertions()[0] is assertion
    response = sel.get_response(0)

    assert response.id == b"cred"
    assert response.response.signature == b"sig"
    assert response.response.user_handle == b"user"
    assert response.client_extension_results["ext"] is True


def test_user_interaction_and_keepalive_prompting():
    ui = client_mod.UserInteraction()
    assert ui.request_pin(client_mod.ClientPin.PERMISSION.GET_ASSERTION, "example.com") is None
    assert ui.request_uv(client_mod.ClientPin.PERMISSION.GET_ASSERTION, "example.com") is True

    prompted = []

    class _UI:
        def prompt_up(self):
            prompted.append(True)

    keepalive = client_mod._user_keepalive(_UI())
    keepalive(STATUS.PROCESSING)
    keepalive(STATUS.UPNEEDED)
    assert prompted == [True]


def test_default_client_data_collector_paths_and_validation():
    collector = client_mod.DefaultClientDataCollector("https://example.com")

    c_opts = _creation_options()
    r_opts = _request_options()

    assert collector.get_rp_id(c_opts, "https://example.com") == "example.com"
    assert collector.get_rp_id(r_opts, "https://example.com") == "example.com"

    c_opts_none = _creation_options(rp={"id": None, "name": "Example"})
    assert collector.get_rp_id(c_opts_none, "https://sub.example.com") == "sub.example.com"

    with pytest.raises(client_mod.ClientError):
        collector.get_rp_id(c_opts_none, "http://invalid.example.com")

    with pytest.raises(ValueError):
        collector.get_rp_id(object(), "https://example.com")

    collector.verify_rp_id("example.com", "https://example.com")

    bad = client_mod.DefaultClientDataCollector(
        "https://example.com", verify=lambda _rp, _origin: False
    )
    with pytest.raises(client_mod.ClientError):
        bad.verify_rp_id("example.com", "https://example.com")

    throws = client_mod.DefaultClientDataCollector(
        "https://example.com", verify=lambda _rp, _origin: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    with pytest.raises(client_mod.ClientError):
        throws.verify_rp_id("example.com", "https://example.com")

    assert collector.get_request_type(c_opts) == CollectedClientData.TYPE.CREATE
    assert collector.get_request_type(r_opts) == CollectedClientData.TYPE.GET
    with pytest.raises(ValueError):
        collector.get_request_type(object())

    client_data, rp_id = collector.collect_client_data(c_opts)
    assert rp_id == "example.com"
    assert client_data.origin == "https://example.com"


def test_cbor_list_and_ctap1_backend_selection_and_error_paths(monkeypatch):
    monkeypatch.setattr(client_mod, "_as_cbor", lambda value: {"wrapped": value})
    assert client_mod._cbor_list(None) is None
    assert client_mod._cbor_list([]) is None
    assert client_mod._cbor_list([{"a": 1}]) == [{"wrapped": {"a": 1}}]

    fake_ctap1 = types.SimpleNamespace(register=lambda *args: b"reg")
    monkeypatch.setattr(client_mod, "Ctap1", lambda _device: fake_ctap1)

    backend = client_mod._Ctap1ClientBackend(types.SimpleNamespace(), client_mod.UserInteraction())

    calls = []
    monkeypatch.setattr(client_mod, "_call_polling", lambda *args, **kwargs: calls.append((args, kwargs)) or b"ok")

    backend.selection(Event())
    assert calls and calls[0][0][3] == fake_ctap1.register

    # Unsupported option branch in do_make_credential.
    opts = _creation_options(authenticatorSelection={"residentKey": "required"})
    with pytest.raises(CtapError) as unsupported:
        backend.do_make_credential(
            opts,
            CollectedClientData.create(
                type=CollectedClientData.TYPE.CREATE,
                origin="https://example.com",
                challenge=b"challenge",
            ),
            "example.com",
            None,
            Event(),
        )
    assert unsupported.value.code == CtapError.ERR.UNSUPPORTED_OPTION

    # Exclude credential branch mapping to DEVICE_INELIGIBLE.
    opts2 = _creation_options(excludeCredentials=[{"type": "public-key", "id": b"cred"}])
    backend.ctap1 = types.SimpleNamespace(
        authenticate=lambda *_args: (_ for _ in ()).throw(ApduError(APDU.USE_NOT_SATISFIED)),
        register=lambda *_args: b"reg",
    )
    with pytest.raises(client_mod.ClientError) as ineligible:
        backend.do_make_credential(
            opts2,
            CollectedClientData.create(
                type=CollectedClientData.TYPE.CREATE,
                origin="https://example.com",
                challenge=b"challenge",
            ),
            "example.com",
            None,
            Event(),
        )
    assert ineligible.value.code == client_mod.ClientError.ERR.DEVICE_INELIGIBLE

    # do_get_assertion unsupported when allow list missing or UV required.
    req_missing_allow = _request_options(allowCredentials=None)
    with pytest.raises(CtapError):
        backend.do_get_assertion(
            req_missing_allow,
            CollectedClientData.create(
                type=CollectedClientData.TYPE.GET,
                origin="https://example.com",
                challenge=b"challenge",
            ),
            "example.com",
            Event(),
        )

    req_uv_required = _request_options(userVerification="required")
    with pytest.raises(CtapError):
        backend.do_get_assertion(
            req_uv_required,
            CollectedClientData.create(
                type=CollectedClientData.TYPE.GET,
                origin="https://example.com",
                challenge=b"challenge",
            ),
            "example.com",
            Event(),
        )
