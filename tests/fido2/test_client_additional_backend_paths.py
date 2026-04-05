from __future__ import annotations

import types

import pytest

import fido2.client as client_mod
from fido2.ctap import CtapError
from fido2.webauthn import (
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
)


class _UI:
    def prompt_up(self):
        return None

    def request_uv(self, _permissions, _rp_id):
        return False

    def request_pin(self, _permissions, _rp_id):
        return "1234"


def _ctap2_info(**overrides):
    data = {
        "versions": [],
        "options": {},
        "pin_uv_protocols": [],
        "max_cred_id_length": None,
        "max_creds_in_list": 1,
    }
    data.update(overrides)
    return types.SimpleNamespace(**data)


def _creation_options(**overrides):
    payload = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"u", "name": "user", "displayName": "User"},
        "challenge": b"challenge",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"userVerification": "discouraged"},
    }
    payload.update(overrides)
    return PublicKeyCredentialCreationOptions.from_dict(payload)


def _request_options(**overrides):
    payload = {
        "challenge": b"challenge",
        "rpId": "example.com",
        "allowCredentials": [{"type": "public-key", "id": b"cred"}],
        "userVerification": "discouraged",
    }
    payload.update(overrides)
    return PublicKeyCredentialRequestOptions.from_dict(payload)


def _make_ctap2_backend(monkeypatch, *, extensions=None):
    info = _ctap2_info()
    ctap2 = types.SimpleNamespace(
        info=info,
        get_info=lambda: info,
        device=types.SimpleNamespace(close=lambda: None, connect=lambda: None),
        make_credential=lambda *_args, **_kwargs: types.SimpleNamespace(
            fmt="none", auth_data=b"auth", att_stmt={}
        ),
        get_assertions=lambda *_args, **_kwargs: [
            types.SimpleNamespace(
                credential={"type": "public-key", "id": b"cred"},
                auth_data=b"auth",
                signature=b"sig",
                user=None,
            )
        ],
    )
    monkeypatch.setattr(client_mod, "Ctap2", lambda _device: ctap2, raising=False)
    backend = client_mod._Ctap2ClientBackend(object(), _UI(), extensions or [])
    return backend, ctap2


def test_ctap1_do_get_assertion_timeout_and_device_ineligible_paths(monkeypatch):
    backend = client_mod._Ctap1ClientBackend(object(), _UI())
    backend.ctap1 = types.SimpleNamespace(authenticate=lambda *_args, **_kwargs: b"auth")

    options = _request_options(
        allowCredentials=[
            {"type": "public-key", "id": b"first"},
            {"type": "public-key", "id": b"second"},
        ]
    )
    client_data = CollectedClientData.create(
        type=CollectedClientData.TYPE.GET,
        challenge=b"challenge",
        origin="https://example.com",
    )

    calls = {"count": 0}

    def _polling(*_args, **_kwargs):
        calls["count"] += 1
        raise client_mod.ClientError.ERR.BAD_REQUEST()

    monkeypatch.setattr(client_mod, "_call_polling", _polling, raising=False)

    with pytest.raises(client_mod.ClientError) as ineligible:
        backend.do_get_assertion(options, client_data, "example.com", None)
    assert ineligible.value.code == client_mod.ClientError.ERR.DEVICE_INELIGIBLE
    assert calls["count"] == 2

    monkeypatch.setattr(
        client_mod,
        "_call_polling",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(client_mod.ClientError.ERR.TIMEOUT()),
        raising=False,
    )
    with pytest.raises(client_mod.ClientError) as timeout_err:
        backend.do_get_assertion(options, client_data, "example.com", None)
    assert timeout_err.value.code == client_mod.ClientError.ERR.TIMEOUT


def test_ctap2_do_make_credential_extension_output_and_error_paths(monkeypatch):
    class _Processor:
        permissions = client_mod.ClientPin.PERMISSION(0)

        def __init__(self, *, output_error=False):
            self._output_error = output_error

        def prepare_inputs(self, _pin_token):
            return {"extInput": True}

        def prepare_outputs(self, _att_resp, _pin_token):
            if self._output_error:
                raise ValueError("bad-output")
            return {"extOutput": True}

    class _Extension:
        def __init__(self, *, output_error=False):
            self._output_error = output_error

        def make_credential(self, _ctap2, _options, _pin_protocol):
            return _Processor(output_error=self._output_error)

    backend, _ctap2 = _make_ctap2_backend(monkeypatch, extensions=[_Extension()])
    backend._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend._filter_creds = lambda *_args, **_kwargs: None

    class _Obj:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    monkeypatch.setattr(client_mod, "AuthenticatorAttestationResponse", _Obj, raising=False)
    monkeypatch.setattr(client_mod, "RegistrationResponse", _Obj, raising=False)
    monkeypatch.setattr(client_mod, "AuthenticationExtensionsClientOutputs", lambda value: value, raising=False)
    monkeypatch.setattr(
        client_mod,
        "AttestationObject",
        types.SimpleNamespace(
            create=lambda *_args, **_kwargs: types.SimpleNamespace(
                auth_data=types.SimpleNamespace(
                    credential_data=types.SimpleNamespace(credential_id=b"cred-id")
                )
            )
        ),
        raising=False,
    )

    response = backend.do_make_credential(
        _creation_options(),
        CollectedClientData.create(
            type=CollectedClientData.TYPE.CREATE,
            challenge=b"challenge",
            origin="https://example.com",
        ),
        "example.com",
        None,
        None,
    )
    assert response.client_extension_results["extOutput"] is True

    backend_err, _ctap2_err = _make_ctap2_backend(monkeypatch, extensions=[_Extension(output_error=True)])
    backend_err._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend_err._filter_creds = lambda *_args, **_kwargs: None
    monkeypatch.setattr(client_mod, "AuthenticatorAttestationResponse", _Obj, raising=False)
    monkeypatch.setattr(client_mod, "RegistrationResponse", _Obj, raising=False)
    monkeypatch.setattr(client_mod, "AuthenticationExtensionsClientOutputs", lambda value: value, raising=False)
    monkeypatch.setattr(
        client_mod,
        "AttestationObject",
        types.SimpleNamespace(
            create=lambda *_args, **_kwargs: types.SimpleNamespace(
                auth_data=types.SimpleNamespace(
                    credential_data=types.SimpleNamespace(credential_id=b"cred-id")
                )
            )
        ),
        raising=False,
    )

    with pytest.raises(client_mod.ClientError) as config_err:
        backend_err.do_make_credential(
            _creation_options(),
            CollectedClientData.create(
                type=CollectedClientData.TYPE.CREATE,
                challenge=b"challenge",
                origin="https://example.com",
            ),
            "example.com",
            None,
            None,
        )
    assert config_err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED


def test_ctap2_do_get_assertion_extension_input_error_and_dummy_allow_credential(monkeypatch):
    class _BadAssertionProcessor:
        permissions = client_mod.ClientPin.PERMISSION(0)

        def prepare_inputs(self, _selected_cred, _pin_token):
            raise ValueError("bad-input")

    class _BadExtension:
        def get_assertion(self, _ctap2, _options, _pin_protocol):
            return _BadAssertionProcessor()

    backend_bad, _ctap2_bad = _make_ctap2_backend(monkeypatch, extensions=[_BadExtension()])
    backend_bad._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend_bad._filter_creds = lambda *_args, **_kwargs: None

    with pytest.raises(client_mod.ClientError) as input_err:
        backend_bad.do_get_assertion(
            _request_options(),
            CollectedClientData.create(
                type=CollectedClientData.TYPE.GET,
                challenge=b"challenge",
                origin="https://example.com",
            ),
            "example.com",
            None,
        )
    assert input_err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED

    backend, ctap2 = _make_ctap2_backend(monkeypatch, extensions=[])
    backend._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend._filter_creds = lambda *_args, **_kwargs: None

    captured_allow = {}

    def _get_assertions(_rp_id, _hash, allow_list, *_args, **_kwargs):
        captured_allow["value"] = allow_list
        return [types.SimpleNamespace(credential={"type": "public-key", "id": b"ok"}, auth_data=b"a", signature=b"s", user=None)]

    ctap2.get_assertions = _get_assertions

    selection = backend.do_get_assertion(
        _request_options(),
        CollectedClientData.create(
            type=CollectedClientData.TYPE.GET,
            challenge=b"challenge",
            origin="https://example.com",
        ),
        "example.com",
        None,
    )
    assert isinstance(selection, client_mod._Ctap2ClientAssertionSelection)
    assert captured_allow["value"][0]["id"] == b"\x00"


def test_fido2client_get_assertion_starts_and_cancels_timeout_timer(monkeypatch):
    class _FakeTimer:
        created = []

        def __init__(self, timeout, callback):
            self.timeout = timeout
            self.callback = callback
            self.daemon = False
            self.started = False
            self.cancelled = False
            _FakeTimer.created.append(self)

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

    backend = types.SimpleNamespace(
        info=types.SimpleNamespace(versions=["FIDO_2_1"], pin_uv_protocols=[]),
        selection=lambda _event: None,
        do_make_credential=lambda *_args, **_kwargs: None,
        do_get_assertion=lambda *_args, **_kwargs: "assertion-selection",
    )

    collector = types.SimpleNamespace(
        collect_client_data=lambda _options: (
            CollectedClientData.create(
                type=CollectedClientData.TYPE.GET,
                challenge=b"challenge",
                origin="https://example.com",
            ),
            "example.com",
        )
    )

    monkeypatch.setattr(client_mod, "_Ctap2ClientBackend", lambda *_args, **_kwargs: backend, raising=False)
    monkeypatch.setattr(client_mod, "_Ctap1ClientBackend", lambda *_args, **_kwargs: backend, raising=False)
    monkeypatch.setattr(client_mod, "Timer", _FakeTimer, raising=False)

    client = client_mod.Fido2Client(object(), collector)
    result = client.get_assertion(_request_options(timeout=25))

    assert result == "assertion-selection"
    assert _FakeTimer.created
    assert _FakeTimer.created[0].started is True
    assert _FakeTimer.created[0].cancelled is True


def test_user_interaction_prompt_and_ctap1_unexpected_authenticate_success(monkeypatch):
    ui = client_mod.UserInteraction()
    ui.prompt_up()

    backend = client_mod._Ctap1ClientBackend(object(), _UI())
    backend.ctap1 = types.SimpleNamespace(
        authenticate=lambda *_args, **_kwargs: b"unexpected-success",
        register=lambda *_args, **_kwargs: b"reg",
    )

    with pytest.raises(client_mod.ClientError) as err:
        backend.do_make_credential(
            _creation_options(excludeCredentials=[{"type": "public-key", "id": b"cred"}]),
            CollectedClientData.create(
                type=CollectedClientData.TYPE.CREATE,
                challenge=b"challenge",
                origin="https://example.com",
            ),
            "example.com",
            None,
            None,
        )

    assert err.value.code == client_mod.ClientError.ERR.OTHER_ERROR


def test_ctap1_do_get_assertion_success_path_and_ctap2_filter_multiple_matches(monkeypatch):
    backend = client_mod._Ctap1ClientBackend(object(), _UI())
    backend.ctap1 = types.SimpleNamespace(authenticate=lambda *_args, **_kwargs: b"auth")

    assertion = types.SimpleNamespace(
        credential={"type": "public-key", "id": b"asserted-id"},
        auth_data=b"auth",
        signature=b"sig",
        user=None,
    )
    monkeypatch.setattr(
        client_mod,
        "_call_polling",
        lambda *_args, **_kwargs: b"auth-response",
        raising=False,
    )
    monkeypatch.setattr(
        client_mod.AssertionResponse,
        "from_ctap1",
        staticmethod(lambda *_args, **_kwargs: assertion),
        raising=False,
    )

    selection = backend.do_get_assertion(
        _request_options(),
        CollectedClientData.create(
            type=CollectedClientData.TYPE.GET,
            challenge=b"challenge",
            origin="https://example.com",
        ),
        "example.com",
        None,
    )
    assert selection.get_assertions()[0] is assertion

    backend2, ctap2 = _make_ctap2_backend(monkeypatch, extensions=[])
    backend2.info.max_creds_in_list = 2
    ctap2.info.max_creds_in_list = 2

    class _Proto:
        VERSION = 1

        def authenticate(self, _token, _message):
            return b"pin-auth"

    ctap2.get_assertions = lambda *_args, **_kwargs: [
        types.SimpleNamespace(credential={"type": "public-key", "id": b"selected"})
    ]

    selected = backend2._filter_creds(
        "example.com",
        [
            PublicKeyCredentialDescriptor(type="public-key", id=b"cred-a"),
            PublicKeyCredentialDescriptor(type="public-key", id=b"cred-b"),
        ],
        _Proto(),
        None,
        None,
        None,
    )

    assert isinstance(selected, PublicKeyCredentialDescriptor)
    assert selected.id == b"selected"