from __future__ import annotations

import types

import pytest

import fido2.ctap2.extensions as ex
from fido2.ctap2.pin import ClientPin
from fido2.webauthn import PublicKeyCredentialDescriptor, ResidentKeyRequirement


class _PinProtocol:
    VERSION = 1

    def encrypt(self, _shared_secret, value):
        return b'enc:' + value

    def authenticate(self, _shared_secret, _value):
        return b'auth'

    def decrypt(self, _shared_secret, value):
        # strip optional mock prefix
        return value[4:] if value.startswith(b'enc:') else value


class _ClientPin:
    PERMISSION = ClientPin.PERMISSION

    def __init__(self, _ctap, _pin_protocol):
        pass

    def _get_shared_secret(self):
        return {'k': 'v'}, b'shared'


def _ctap(*, extensions=None, options=None, max_cred_blob_length=64):
    return types.SimpleNamespace(
        info=types.SimpleNamespace(
            extensions=extensions or [],
            options=options or {},
            max_cred_blob_length=max_cred_blob_length,
        )
    )


def _descriptor(cred_id=b'cred'):
    return PublicKeyCredentialDescriptor(type='public-key', id=cred_id)


def test_extension_processors_and_hmac_helper_functions():
    reg = ex.RegistrationExtensionProcessor(inputs={'a': 1}, outputs={'b': 2})
    auth = ex.AuthenticationExtensionProcessor(inputs={'x': 1}, outputs={'y': 2})

    assert reg.prepare_inputs(None) == {'a': 1}
    assert reg.prepare_outputs(types.SimpleNamespace(), None) == {'b': 2}
    assert auth.prepare_inputs(None, None) == {'x': 1}
    assert auth.prepare_outputs(types.SimpleNamespace(), None) == {'y': 2}

    secret = b'a' * 32
    assert ex._prf_salt(secret) == ex.sha256(b'WebAuthn PRF\0' + secret)

    prf = ex.AuthenticatorExtensionsPRFInputs(eval=ex.AuthenticatorExtensionsPRFValues(secret))
    salts = ex._hmac_prepare_salts(None, None, prf, None)
    assert salts and len(salts[0]) == ex.HmacSecretExtension.SALT_LEN

    hmac = ex.HMACGetSecretInput(salt1=secret, salt2=secret)
    salts_hmac = ex._hmac_prepare_salts(None, None, None, hmac)
    assert salts_hmac == (secret, secret)

    outputs = ex._hmac_format_outputs(True, b'1' * 64, prf)
    assert 'prf' in outputs

    legacy = ex._hmac_format_outputs(True, b'1' * 64, None)
    assert legacy and 'hmacCreateSecret' in legacy and 'hmacGetSecret' in legacy


def test_hmac_prepare_salts_validation_errors():
    prf = ex.AuthenticatorExtensionsPRFInputs(
        eval_by_credential={'bad': ex.AuthenticatorExtensionsPRFValues(b'a' * 32)}
    )

    with pytest.raises(ValueError, match='allowCredentials'):
        ex._hmac_prepare_salts(None, None, prf, None)

    allow_list = [_descriptor(b'good')]
    with pytest.raises(ValueError, match='invalid key'):
        ex._hmac_prepare_salts(allow_list, None, prf, None)

    short_hmac = ex.HMACGetSecretInput(salt1=b'short')
    with pytest.raises(ValueError, match='Invalid salt length'):
        ex._hmac_prepare_salts(None, None, None, short_hmac)


def test_hmac_secret_extension_make_credential_and_get_assertion(monkeypatch):
    monkeypatch.setattr(ex, 'ClientPin', _ClientPin)

    ctap = _ctap(extensions=[ex.HmacSecretExtension.NAME, ex.HmacSecretExtension.MC_NAME])
    pin = _PinProtocol()
    extension = ex.HmacSecretExtension(allow_hmac_secret=True)

    options = types.SimpleNamespace(
        extensions={
            'prf': {'eval': {'first': b'a' * 32}},
            'hmacCreateSecret': True,
            'hmacGetSecret': {'salt1': b'a' * 32},
        },
        allow_credentials=[_descriptor(b'cred')],
    )

    processor = extension.make_credential(ctap, options, pin)
    assert processor is not None

    inputs = processor.prepare_inputs(None)
    assert ex.HmacSecretExtension.NAME in inputs
    assert ex.HmacSecretExtension.MC_NAME in inputs

    response = types.SimpleNamespace(
        auth_data=types.SimpleNamespace(
            extensions={
                ex.HmacSecretExtension.NAME: True,
                ex.HmacSecretExtension.MC_NAME: b'enc:' + (b'X' * 64),
            }
        )
    )
    outputs = processor.prepare_outputs(response, None)
    assert outputs and 'prf' in outputs

    assertion_processor = extension.get_assertion(ctap, options, pin)
    assert assertion_processor is not None

    a_inputs = assertion_processor.prepare_inputs(_descriptor(b'cred'), None)
    assert ex.HmacSecretExtension.NAME in a_inputs

    a_response = types.SimpleNamespace(
        auth_data=types.SimpleNamespace(extensions={ex.HmacSecretExtension.NAME: b'enc:' + (b'Y' * 64)})
    )
    a_outputs = assertion_processor.prepare_outputs(a_response, None)
    assert a_outputs and 'prf' in a_outputs

    # unsupported / missing pin protocol returns None
    assert extension.make_credential(_ctap(extensions=[]), options, pin) is None
    assert extension.get_assertion(ctap, options, None) is None


def test_large_blob_extension_paths(monkeypatch):
    extension = ex.LargeBlobExtension()
    ctap_supported = _ctap(extensions=[ex.LargeBlobExtension.NAME], options={'largeBlobs': True})
    ctap_unsupported = _ctap(extensions=[], options={'largeBlobs': False})

    assert extension.is_supported(ctap_supported) is True
    assert extension.is_supported(ctap_unsupported) is False

    with pytest.raises(ValueError, match='Invalid set of parameters'):
        extension.make_credential(
            ctap_supported,
            types.SimpleNamespace(extensions={'largeBlob': {'read': True}}, allow_credentials=[]),
            _PinProtocol(),
        )

    with pytest.raises(ValueError, match='does not support large blob storage'):
        extension.make_credential(
            ctap_unsupported,
            types.SimpleNamespace(extensions={'largeBlob': {'support': 'required'}}, allow_credentials=[]),
            _PinProtocol(),
        )

    proc = extension.make_credential(
        ctap_supported,
        types.SimpleNamespace(extensions={'largeBlob': {'support': 'preferred'}}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert proc is not None
    out = proc.prepare_outputs(types.SimpleNamespace(large_blob_key=b'k'), None)
    assert out['largeBlob'].supported is True

    with pytest.raises(ValueError, match='Invalid set of parameters'):
        extension.get_assertion(
            ctap_supported,
            types.SimpleNamespace(extensions={'largeBlob': {'support': 'x', 'read': True}}, allow_credentials=[]),
            _PinProtocol(),
        )

    with pytest.raises(ValueError, match='does not support large blob storage'):
        extension.get_assertion(
            ctap_unsupported,
            types.SimpleNamespace(extensions={'largeBlob': {'read': True}}, allow_credentials=[]),
            _PinProtocol(),
        )

    calls = []

    class _LargeBlobs:
        def __init__(self, *_args):
            pass

        def get_blob(self, key):
            calls.append(('get', key))
            return b'blob'

        def put_blob(self, key, data):
            calls.append(('put', key, data))

    monkeypatch.setattr(ex, 'LargeBlobs', _LargeBlobs)

    read_proc = extension.get_assertion(
        ctap_supported,
        types.SimpleNamespace(extensions={'largeBlob': {'read': True}}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert read_proc is not None
    read_out = read_proc.prepare_outputs(types.SimpleNamespace(large_blob_key=b'k'), b'token')
    assert read_out['largeBlob'].blob == b'blob'

    write_proc = extension.get_assertion(
        ctap_supported,
        types.SimpleNamespace(extensions={'largeBlob': {'write': b'data'}}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert write_proc.permissions == ClientPin.PERMISSION.LARGE_BLOB_WRITE
    write_out = write_proc.prepare_outputs(types.SimpleNamespace(large_blob_key=b'k'), b'token')
    assert write_out['largeBlob'].written is True

    assert calls == [('get', b'k'), ('put', b'k', b'data')]


def test_credblob_credprotect_minpin_credprops_and_payment_extensions():
    ctap = _ctap(
        extensions=['credBlob', 'credProtect', 'thirdPartyPayment'],
        options={'setMinPINLength': True, 'rk': True},
        max_cred_blob_length=8,
    )

    cred_blob = ex.CredBlobExtension()
    proc = cred_blob.make_credential(
        ctap,
        types.SimpleNamespace(extensions={'credBlob': b'1234'}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert proc and proc.prepare_inputs(None) == {'credBlob': b'1234'}
    assert cred_blob.make_credential(
        ctap,
        types.SimpleNamespace(extensions={'credBlob': b'0123456789'}, allow_credentials=[]),
        _PinProtocol(),
    ) is None
    a_proc = cred_blob.get_assertion(
        ctap,
        types.SimpleNamespace(extensions={'getCredBlob': True}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert a_proc and a_proc.prepare_inputs(None, None) == {'credBlob': True}

    cred_protect = ex.CredProtectExtension()
    with pytest.raises(ValueError, match='does not support Credential Protection'):
        cred_protect.make_credential(
            _ctap(extensions=[]),
            types.SimpleNamespace(
                extensions={
                    'credentialProtectionPolicy': ex.CredProtectExtension.POLICY.REQUIRED.value,
                    'enforceCredentialProtectionPolicy': True,
                },
                allow_credentials=[],
            ),
            _PinProtocol(),
        )

    cp_proc = cred_protect.make_credential(
        ctap,
        types.SimpleNamespace(
            extensions={'credentialProtectionPolicy': ex.CredProtectExtension.POLICY.OPTIONAL.value},
            allow_credentials=[],
        ),
        _PinProtocol(),
    )
    assert cp_proc and cp_proc.prepare_inputs(None) == {'credProtect': 1}

    min_pin = ex.MinPinLengthExtension()
    assert min_pin.is_supported(ctap) is True
    assert min_pin.make_credential(ctap, types.SimpleNamespace(extensions={'minPinLength': False}), _PinProtocol()) is None
    mp_proc = min_pin.make_credential(
        ctap,
        types.SimpleNamespace(extensions={'minPinLength': True}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert mp_proc and mp_proc.prepare_inputs(None) == {'minPinLength': True}

    cred_props = ex.CredPropsExtension()
    cp = cred_props.make_credential(
        ctap,
        types.SimpleNamespace(
            extensions={'credProps': True},
            authenticator_selection=types.SimpleNamespace(resident_key=ResidentKeyRequirement.REQUIRED),
        ),
        _PinProtocol(),
    )
    assert cp and cp.prepare_outputs(types.SimpleNamespace(), None)['credProps'].rk is True

    payment = ex.ThirdPartyPaymentExtension()
    p_proc = payment.make_credential(
        ctap,
        types.SimpleNamespace(extensions={'payment': {'isPayment': True}}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert p_proc and p_proc.prepare_inputs(None) == {'thirdPartyPayment': True}

    p_get = payment.get_assertion(
        ctap,
        types.SimpleNamespace(extensions={'payment': {'isPayment': True}}, allow_credentials=[]),
        _PinProtocol(),
    )
    assert p_get and p_get.prepare_inputs(None, None) == {'thirdPartyPayment': True}

    # defaults list sanity
    assert any(isinstance(ext, ex.HmacSecretExtension) for ext in ex._DEFAULT_EXTENSIONS)


def test_extensions_additional_branch_paths(monkeypatch):
    class _DummyExtension(ex.Ctap2Extension):
        def is_supported(self, ctap):
            return False

    dummy = _DummyExtension()
    opts = types.SimpleNamespace(extensions={}, allow_credentials=[])
    assert dummy.make_credential(_ctap(), opts, None) is None
    assert dummy.get_assertion(_ctap(), opts, None) is None

    # _hmac_prepare_salts selected evalByCredential path + empty/no-input exits
    selected = _descriptor(b'selected')
    selected_key = ex.websafe_encode(selected.id)
    prf_by_cred = ex.AuthenticatorExtensionsPRFInputs(
        eval_by_credential={selected_key: ex.AuthenticatorExtensionsPRFValues(b'a' * 32)}
    )
    salts = ex._hmac_prepare_salts([selected], selected, prf_by_cred, None)
    assert salts and len(salts[0]) == ex.HmacSecretExtension.SALT_LEN

    prf_selected_miss = ex.AuthenticatorExtensionsPRFInputs(
        eval=ex.AuthenticatorExtensionsPRFValues(b'b' * 32),
        eval_by_credential={
            ex.websafe_encode(_descriptor(b'other').id): ex.AuthenticatorExtensionsPRFValues(b'a' * 32)
        },
    )
    salts_selected_miss = ex._hmac_prepare_salts(
        [selected, _descriptor(b'other')],
        selected,
        prf_selected_miss,
        None,
    )
    assert salts_selected_miss and len(salts_selected_miss[0]) == ex.HmacSecretExtension.SALT_LEN

    prf_no_selected = ex.AuthenticatorExtensionsPRFInputs(
        eval=ex.AuthenticatorExtensionsPRFValues(b'c' * 32),
        eval_by_credential={selected_key: ex.AuthenticatorExtensionsPRFValues(b'a' * 32)},
    )
    salts_no_selected = ex._hmac_prepare_salts([selected], None, prf_no_selected, None)
    assert salts_no_selected and len(salts_no_selected[0]) == ex.HmacSecretExtension.SALT_LEN

    assert ex._hmac_prepare_salts(None, None, ex.AuthenticatorExtensionsPRFInputs(), None) is None
    assert ex._hmac_prepare_salts(None, None, None, None) is None
    assert ex._hmac_format_outputs(None, None, None) is None

    monkeypatch.setattr(ex, 'ClientPin', _ClientPin)
    pin = _PinProtocol()
    hmac_ext = ex.HmacSecretExtension(allow_hmac_secret=True)

    # make_credential branch where MC_NAME is absent
    ctap_no_mc = _ctap(extensions=[ex.HmacSecretExtension.NAME])
    p_no_mc = hmac_ext.make_credential(
        ctap_no_mc,
        types.SimpleNamespace(extensions={'prf': {'eval': {'first': b'a' * 32}}, 'hmacCreateSecret': False}),
        pin,
    )
    assert p_no_mc and ex.HmacSecretExtension.MC_NAME not in p_no_mc.prepare_inputs(None)

    # make_credential branch where salts are absent despite MC support
    ctap_with_mc = _ctap(extensions=[ex.HmacSecretExtension.NAME, ex.HmacSecretExtension.MC_NAME])
    p_no_salts = hmac_ext.make_credential(
        ctap_with_mc,
        types.SimpleNamespace(extensions={'prf': {}}, allow_credentials=[selected]),
        pin,
    )
    assert p_no_salts and ex.HmacSecretExtension.MC_NAME not in p_no_salts.prepare_inputs(None)

    # get_assertion prepare_inputs no-salts branch
    g_no_salts = hmac_ext.get_assertion(
        ctap_with_mc,
        types.SimpleNamespace(
            extensions={
                'prf': {
                    'evalByCredential': {
                        ex.websafe_encode(_descriptor(b'other').id): {'first': b'a' * 32}
                    }
                }
            },
            allow_credentials=[selected, _descriptor(b'other')],
        ),
        pin,
    )
    assert g_no_salts and g_no_salts.prepare_inputs(selected, None) is None

    # LargeBlob no-op branches
    large_blob = ex.LargeBlobExtension()
    ctap_large = _ctap(extensions=[ex.LargeBlobExtension.NAME], options={'largeBlobs': True})
    assert (
        large_blob.make_credential(
            ctap_large,
            types.SimpleNamespace(extensions={}, allow_credentials=[]),
            pin,
        )
        is None
    )

    proc = large_blob.make_credential(
        ctap_large,
        types.SimpleNamespace(extensions={'largeBlob': {'support': 'preferred'}}, allow_credentials=[]),
        pin,
    )
    assert proc and proc.prepare_inputs(None) == {ex.LargeBlobExtension.NAME: True}

    g_proc = large_blob.get_assertion(
        ctap_large,
        types.SimpleNamespace(extensions={'largeBlob': {'read': True}}, allow_credentials=[]),
        pin,
    )
    assert g_proc and g_proc.prepare_outputs(types.SimpleNamespace(large_blob_key=None), b'token') is None

    assert (
        large_blob.get_assertion(
            ctap_large,
            types.SimpleNamespace(extensions={}, allow_credentials=[]),
            pin,
        )
        is None
    )

    g_no_read_write = large_blob.get_assertion(
        ctap_large,
        types.SimpleNamespace(extensions={'largeBlob': {'read': False}}, allow_credentials=[]),
        pin,
    )
    assert g_no_read_write and g_no_read_write.prepare_outputs(types.SimpleNamespace(large_blob_key=b'k'), b'token') is None

    # CredBlob unsupported/no-input branches
    cred_blob = ex.CredBlobExtension()
    assert (
        cred_blob.make_credential(
            _ctap(extensions=[]),
            types.SimpleNamespace(extensions={'credBlob': b'data'}),
            pin,
        )
        is None
    )
    assert (
        cred_blob.get_assertion(
            _ctap(extensions=[]),
            types.SimpleNamespace(extensions={'getCredBlob': True}),
            pin,
        )
        is None
    )

    cred_protect = ex.CredProtectExtension()
    assert cred_protect.make_credential(ctap_large, types.SimpleNamespace(extensions={}), pin) is None

    cred_props = ex.CredPropsExtension()
    assert cred_props.is_supported(ctap_large) is True
    assert (
        cred_props.make_credential(
            ctap_large,
            types.SimpleNamespace(extensions={}, authenticator_selection=None),
            pin,
        )
        is None
    )

    payment = ex.ThirdPartyPaymentExtension()
    assert (
        payment.make_credential(
            _ctap(extensions=[]),
            types.SimpleNamespace(extensions={'payment': {'isPayment': True}}),
            pin,
        )
        is None
    )
    assert (
        payment.get_assertion(
            _ctap(extensions=[]),
            types.SimpleNamespace(extensions={'payment': {'isPayment': True}}),
            pin,
        )
        is None
    )
