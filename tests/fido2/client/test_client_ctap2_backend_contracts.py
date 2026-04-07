from __future__ import annotations

import types

import pytest

import fido2.client as client_mod
from fido2.ctap import CtapError
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)


class _UI:
    def __init__(self, *, uv=True, pin='1234'):
        self._uv = uv
        self._pin = pin
        self.prompted = 0

    def prompt_up(self):
        self.prompted += 1

    def request_uv(self, _permissions, _rp_id):
        return self._uv

    def request_pin(self, _permissions, _rp_id):
        return self._pin


def _info(**overrides):
    data = {
        'versions': [],
        'options': {},
        'pin_uv_protocols': [],
        'max_cred_id_length': None,
        'max_creds_in_list': 2,
    }
    data.update(overrides)
    return types.SimpleNamespace(**data)


def _descriptor(cred_id=b'cred'):
    return PublicKeyCredentialDescriptor(type='public-key', id=cred_id)


def _make_backend(monkeypatch, *, info=None, extensions=None, ui=None):
    device = types.SimpleNamespace()
    info_obj = info or _info()

    ctap = types.SimpleNamespace(
        info=info_obj,
        device=types.SimpleNamespace(close=lambda: None, connect=lambda: None),
    )
    ctap.get_info = lambda: info_obj
    ctap.selection = lambda **_kwargs: None
    ctap.make_credential = lambda *_args, **_kwargs: types.SimpleNamespace(
        fmt='none', auth_data=b'auth', att_stmt={}
    )
    ctap.get_assertions = lambda *_args, **_kwargs: [
        types.SimpleNamespace(
            credential={'type': 'public-key', 'id': b'asserted'},
            auth_data=b'auth',
            signature=b'sig',
            user=None,
        )
    ]

    monkeypatch.setattr(client_mod, 'Ctap2', lambda _device: ctap)
    backend = client_mod._Ctap2ClientBackend(
        device,
        ui or _UI(),
        extensions or [],
    )
    return backend, ctap


def _creation_options(**overrides):
    kwargs = {
        'rp': {'id': 'example.com', 'name': 'Example'},
        'user': {'id': b'u', 'name': 'user', 'displayName': 'User'},
        'challenge': b'challenge',
        'pub_key_cred_params': [{'type': 'public-key', 'alg': -7}],
        'authenticator_selection': {
            'userVerification': 'discouraged',
            'residentKey': 'required',
        },
        'attestation': 'enterprise',
    }
    kwargs.update(overrides)
    return PublicKeyCredentialCreationOptions(**kwargs)


def _request_options(**overrides):
    kwargs = {
        'challenge': b'challenge',
        'rp_id': 'example.com',
        'allow_credentials': [{'type': 'public-key', 'id': b'allow'}],
        'user_verification': 'discouraged',
    }
    kwargs.update(overrides)
    return PublicKeyCredentialRequestOptions(**kwargs)


def test_ctap2_assertion_selection_extension_output_paths():
    ex1 = types.SimpleNamespace(prepare_outputs=lambda _a, _p: {'a': 1})
    ex2 = types.SimpleNamespace(prepare_outputs=lambda _a, _p: {'b': 2})

    sel = client_mod._Ctap2ClientAssertionSelection(
        types.SimpleNamespace(),
        [],
        [ex1, ex2],
        b'token',
    )
    assert sel._get_extension_results(types.SimpleNamespace()) == {'a': 1, 'b': 2}

    def _raise_value_error(_a, _p):
        raise ValueError('bad output')

    bad = types.SimpleNamespace(prepare_outputs=_raise_value_error)
    bad_sel = client_mod._Ctap2ClientAssertionSelection(
        types.SimpleNamespace(),
        [],
        [bad],
        b'token',
    )
    with pytest.raises(client_mod.ClientError) as err:
        bad_sel._get_extension_results(types.SimpleNamespace())
    assert err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED


def test_ctap2_filter_creds_and_selection_paths(monkeypatch):
    backend, ctap = _make_backend(monkeypatch, info=_info(max_cred_id_length=2, max_creds_in_list=2))

    class _Proto:
        VERSION = 1

        def authenticate(self, _token, _msg):
            return b'auth'

    # max_cred_id_length filter + len(chunk)==1 branch
    ctap.get_assertions = lambda *_args, **_kwargs: []
    c1 = _descriptor(b'a')
    c2 = _descriptor(b'abc')
    selected = backend._filter_creds('example.com', [c1, c2], _Proto(), b'tok', None, None)
    assert selected.id == b'a'

    # REQUEST_TOO_LARGE then fallback to smaller chunk
    calls = {'n': 0}

    def _request_too_large_then_ok(*_args, **_kwargs):
        calls['n'] += 1
        if calls['n'] == 1:
            raise CtapError(CtapError.ERR.REQUEST_TOO_LARGE)
        return []

    ctap.get_assertions = _request_too_large_then_ok
    selected2 = backend._filter_creds('example.com', [c1, _descriptor(b'b')], _Proto(), None, None, None)
    assert selected2.id == b'a'

    # NO_CREDENTIALS exhausts chunks -> None
    ctap.get_assertions = lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.NO_CREDENTIALS))
    assert backend._filter_creds('example.com', [_descriptor(b'a'), _descriptor(b'b')], _Proto(), None, None, None) is None

    # unexpected errors are re-raised
    ctap.get_assertions = lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND))
    with pytest.raises(CtapError):
        backend._filter_creds('example.com', [_descriptor(b'a')], _Proto(), None, None, None)

    # selection path with FIDO_2_1 support
    called = []
    ctap.info.versions = ['FIDO_2_1']
    ctap.selection = lambda **_kwargs: called.append('selection')
    backend.selection(None)
    assert called == ['selection']

    # fallback dummy make_credential with tolerated errors
    ctap.info.versions = []
    ctap.make_credential = lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.PIN_NOT_SET))
    backend.selection(None)

    ctap.make_credential = lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_OPTION))
    with pytest.raises(CtapError):
        backend.selection(None)


def test_ctap2_uv_decision_token_and_auth_helpers(monkeypatch):
    backend, _ctap = _make_backend(monkeypatch, info=_info(options={'uv': True, 'clientPin': True}))

    # _should_use_uv branches
    with pytest.raises(client_mod.ClientError) as err:
        backend._should_use_uv(
            _info(options={'uv': False}),
            UserVerificationRequirement.REQUIRED,
            client_mod.ClientPin.PERMISSION.GET_ASSERTION,
        )
    assert err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED

    assert backend._should_use_uv(
        _info(options={'uv': True}),
        UserVerificationRequirement.PREFERRED,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION,
    ) is True

    assert backend._should_use_uv(
        _info(options={'clientPin': True, 'makeCredUvNotRqd': False}),
        UserVerificationRequirement.DISCOURAGED,
        client_mod.ClientPin.PERMISSION.MAKE_CREDENTIAL,
    ) is True

    assert backend._should_use_uv(
        _info(options={'clientPin': True}),
        UserVerificationRequirement.DISCOURAGED,
        client_mod.ClientPin.PERMISSION.LARGE_BLOB_WRITE,
    ) is True

    assert backend._should_use_uv(
        _info(options={}),
        UserVerificationRequirement.DISCOURAGED,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION,
    ) is False

    class _ClientPin:
        def get_uv_token(self, *_args):
            return b'uv-token'

        def get_pin_token(self, *_args):
            return b'pin-token'

    cp = _ClientPin()
    ui = backend.user_interaction

    monkeypatch.setattr(client_mod.ClientPin, 'is_token_supported', staticmethod(lambda _info: True))
    token = backend._get_token(
        _info(options={'uv': True}), cp,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION,
        'example.com', None, None, True, True,
    )
    assert token == b'uv-token'

    monkeypatch.setattr(client_mod.ClientPin, 'is_token_supported', staticmethod(lambda _info: False))
    ui._uv = True
    assert backend._get_token(
        _info(options={'uv': True}), cp,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION,
        'example.com', None, None, True, True,
    ) is None

    ui._pin = '1234'
    assert backend._get_token(
        _info(options={'clientPin': True}), cp,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION,
        'example.com', None, None, True, False,
    ) == b'pin-token'

    ui._pin = ''
    with pytest.raises(client_mod.PinRequiredError):
        backend._get_token(
            _info(options={'clientPin': True}), cp,
            client_mod.ClientPin.PERMISSION.GET_ASSERTION,
            'example.com', None, None, True, False,
        )

    with pytest.raises(client_mod.ClientError) as err2:
        backend._get_token(
            _info(options={}), cp,
            client_mod.ClientPin.PERMISSION.GET_ASSERTION,
            'example.com', None, None, True, False,
        )
    assert err2.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED

    # _get_auth_params no-UV and internal-UV paths
    backend._should_use_uv = lambda *_args, **_kwargs: False
    token2, internal2 = backend._get_auth_params(
        types.SimpleNamespace(), 'example.com', UserVerificationRequirement.DISCOURAGED,
        client_mod.ClientPin.PERMISSION.GET_ASSERTION, True, None, None,
    )
    assert token2 is None and internal2 is False

    class _PatchedClientPin:
        PERMISSION = client_mod.ClientPin.PERMISSION

        def __init__(self, *_args):
            pass

    monkeypatch.setattr(client_mod, 'ClientPin', _PatchedClientPin)
    backend._should_use_uv = lambda *_args, **_kwargs: True
    backend._get_token = lambda *_args, **_kwargs: None
    token3, internal3 = backend._get_auth_params(
        types.SimpleNamespace(), 'example.com', UserVerificationRequirement.DISCOURAGED,
        _PatchedClientPin.PERMISSION.GET_ASSERTION, True, None, None,
    )
    assert token3 is None and internal3 is True


def test_ctap2_do_get_assertion_dummy_cred_and_retry_loop(monkeypatch):
    info = _info(pin_uv_protocols=[])
    backend, ctap = _make_backend(monkeypatch, info=info, extensions=[])

    backend._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend._filter_creds = lambda *_args, **_kwargs: None

    calls = {'n': 0}
    seen_allow = []
    device_state = {'closed': 0, 'connected': 0}
    ctap.device.close = lambda: device_state.__setitem__('closed', device_state['closed'] + 1)
    ctap.device.connect = lambda: device_state.__setitem__('connected', device_state['connected'] + 1)

    def _get_assertions(_rp_id, _hash, allow, _ext, _opts, *_args, **_kwargs):
        calls['n'] += 1
        seen_allow.append(allow)
        if calls['n'] == 1:
            raise CtapError(CtapError.ERR.PUAT_REQUIRED)
        if calls['n'] == 2:
            raise CtapError(CtapError.ERR.UV_BLOCKED)
        if calls['n'] == 3:
            raise CtapError(CtapError.ERR.PIN_AUTH_BLOCKED)
        return [
            types.SimpleNamespace(
                credential={'type': 'public-key', 'id': b'ok'},
                auth_data=b'a',
                signature=b's',
                user=None,
            )
        ]

    ctap.get_assertions = _get_assertions

    options = _request_options()
    result = backend.do_get_assertion(
        options,
        types.SimpleNamespace(hash=b'h' * 32),
        'ignored-rp-id',
        None,
    )
    assert isinstance(result, client_mod._Ctap2ClientAssertionSelection)
    assert calls['n'] == 4
    # dummy allow credential branch sends a non-empty allow list when selected cred is None
    assert seen_allow[-1] is not None
    assert device_state == {'closed': 1, 'connected': 1}

    # extension input ValueError -> configuration unsupported
    bad_ext = types.SimpleNamespace(
        get_assertion=lambda *_args, **_kwargs: types.SimpleNamespace(
            permissions=client_mod.ClientPin.PERMISSION(0),
            prepare_inputs=lambda *_a, **_k: (_ for _ in ()).throw(ValueError('bad ext inputs')),
        )
    )
    backend_bad, ctap_bad = _make_backend(monkeypatch, info=info, extensions=[bad_ext])
    backend_bad._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend_bad._filter_creds = lambda *_args, **_kwargs: None
    ctap_bad.get_assertions = lambda *_args, **_kwargs: []
    with pytest.raises(client_mod.ClientError) as err:
        backend_bad.do_get_assertion(options, types.SimpleNamespace(hash=b'h' * 32), 'rp', None)
    assert err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED


def test_ctap2_do_make_credential_retry_and_configuration_paths(monkeypatch):
    info = _info(options={'ep': True, 'rk': True}, pin_uv_protocols=[])
    backend, ctap = _make_backend(monkeypatch, info=info, extensions=[])

    backend._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend._filter_creds = lambda *_args, **_kwargs: _descriptor(b'excluded')

    device_state = {'closed': 0, 'connected': 0}
    ctap.device.close = lambda: device_state.__setitem__('closed', device_state['closed'] + 1)
    ctap.device.connect = lambda: device_state.__setitem__('connected', device_state['connected'] + 1)

    calls = {'n': 0}

    def _make_credential(*_args, **_kwargs):
        calls['n'] += 1
        if calls['n'] == 1:
            raise CtapError(CtapError.ERR.PUAT_REQUIRED)
        if calls['n'] == 2:
            raise CtapError(CtapError.ERR.UV_BLOCKED)
        if calls['n'] == 3:
            raise CtapError(CtapError.ERR.PIN_AUTH_BLOCKED)
        return types.SimpleNamespace(fmt='none', auth_data=b'a', att_stmt={})

    ctap.make_credential = _make_credential

    class _Obj:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    monkeypatch.setattr(client_mod, 'AuthenticatorAttestationResponse', _Obj)
    monkeypatch.setattr(client_mod, 'RegistrationResponse', _Obj)
    monkeypatch.setattr(client_mod, 'AuthenticationExtensionsClientOutputs', lambda value: value)
    monkeypatch.setattr(
        client_mod,
        'AttestationObject',
        types.SimpleNamespace(
            create=lambda *_args, **_kwargs: types.SimpleNamespace(
                auth_data=types.SimpleNamespace(
                    credential_data=types.SimpleNamespace(credential_id=b'cred-id')
                )
            )
        ),
    )

    options = _creation_options(
        exclude_credentials=[{'type': 'public-key', 'id': b'excluded'}],
    )

    result = backend.do_make_credential(
        options,
        types.SimpleNamespace(hash=b'h' * 32),
        'example.com',
        ['example.com'],
        None,
    )
    assert result.id == b'cred-id'
    assert calls['n'] == 4
    assert device_state == {'closed': 1, 'connected': 1}

    # rk required but authenticator doesn't support rk -> configuration unsupported
    backend_no_rk, _ctap_no_rk = _make_backend(monkeypatch, info=_info(options={'rk': False}, pin_uv_protocols=[]), extensions=[])
    backend_no_rk._get_auth_params = lambda *_args, **_kwargs: (None, False)
    backend_no_rk._filter_creds = lambda *_args, **_kwargs: None
    with pytest.raises(client_mod.ClientError) as err:
        backend_no_rk.do_make_credential(options, types.SimpleNamespace(hash=b'h' * 32), 'example.com', None, None)
    assert err.value.code == client_mod.ClientError.ERR.CONFIGURATION_UNSUPPORTED


def test_fido2client_wrapper_fallback_and_error_mapping(monkeypatch):
    collector = types.SimpleNamespace(
        collect_client_data=lambda _options: (types.SimpleNamespace(hash=b'h' * 32), 'example.com')
    )

    fallback_backend = types.SimpleNamespace(
        info=types.SimpleNamespace(versions=['U2F_V2']),
        selection=lambda _event: None,
        do_make_credential=lambda *_args, **_kwargs: 'mk',
        do_get_assertion=lambda *_args, **_kwargs: 'ga',
    )

    monkeypatch.setattr(client_mod, '_Ctap2ClientBackend', lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError('no ctap2')))
    monkeypatch.setattr(client_mod, '_Ctap1ClientBackend', lambda *_args, **_kwargs: fallback_backend)
    client = client_mod.Fido2Client(types.SimpleNamespace(), collector)
    assert client.info.versions == ['U2F_V2']

    primary_backend = types.SimpleNamespace(
        info=types.SimpleNamespace(versions=['FIDO_2_1']),
        selection=lambda _event: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_OPTION)),
        do_make_credential=lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED)),
        do_get_assertion=lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
    )

    monkeypatch.setattr(client_mod, '_Ctap2ClientBackend', lambda *_args, **_kwargs: primary_backend)
    monkeypatch.setattr(client_mod, '_Ctap1ClientBackend', lambda *_args, **_kwargs: fallback_backend)
    client2 = client_mod.Fido2Client(types.SimpleNamespace(), collector)

    with pytest.raises(client_mod.ClientError) as sel_err:
        client2.selection()
    assert sel_err.value.code == client_mod.ClientError.ERR.BAD_REQUEST

    with pytest.raises(client_mod.ClientError) as mk_err:
        client2.make_credential(_creation_options())
    assert mk_err.value.code == client_mod.ClientError.ERR.DEVICE_INELIGIBLE

    with pytest.raises(client_mod.ClientError) as ga_err:
        client2.get_assertion(_request_options())
    assert ga_err.value.code == client_mod.ClientError.ERR.BAD_REQUEST
