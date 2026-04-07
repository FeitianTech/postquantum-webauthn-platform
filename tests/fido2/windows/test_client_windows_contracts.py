from __future__ import annotations

import importlib.util
import sys
import types
from enum import IntEnum
from pathlib import Path
from threading import Event

import pytest

from fido2.client import ClientError
from fido2.cose import ES256
from fido2.ctap2.extensions import (
    AuthenticatorExtensionsLargeBlobOutputs,
    AuthenticatorExtensionsPRFOutputs,
    CredentialPropertiesOutput,
    HMACGetSecretOutput,
)
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


def _repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "fido2" / "client" / "windows.py").is_file():
            return candidate
    raise FileNotFoundError("Unable to locate repository root containing fido2/client/windows.py")


class _FromStringEnum(IntEnum):
    @classmethod
    def from_string(cls, value: str):
        return getattr(cls, value.upper().replace("-", "_"))


class _FakeBOOL:
    def __init__(self, value=False):
        self.value = bool(value)

    def __bool__(self):
        return self.value


class _Collector:
    def collect_client_data(self, options):
        request_type = (
            CollectedClientData.TYPE.CREATE
            if isinstance(options, PublicKeyCredentialCreationOptions)
            else CollectedClientData.TYPE.GET
        )
        return (
            CollectedClientData.create(
                type=request_type,
                challenge=options.challenge,
                origin="https://example.com",
            ),
            "example.com",
        )


class _FakeCancelThread:
    instances = []

    def __init__(self, event):
        self.event = event
        self.guid = "cancel-guid"
        self.started = False
        self.completed = False
        self.__class__.instances.append(self)

    def start(self):
        self.started = True

    def complete(self):
        self.completed = True


class _FakeWebAuthnApi:
    def __init__(self):
        self.get_cancellation_id_calls = 0
        self.cancel_current_calls = 0
        self.last_make_credential_call = None
        self.last_get_assertion_call = None
        self._make_impl = None
        self._get_impl = None

    def set_make_impl(self, impl):
        self._make_impl = impl

    def set_get_impl(self, impl):
        self._get_impl = impl

    def WebAuthNGetCancellationId(self, _guid):
        self.get_cancellation_id_calls += 1
        return 0

    def WebAuthNCancelCurrentOperation(self, _guid):
        self.cancel_current_calls += 1
        return 0

    def WebAuthNAuthenticatorMakeCredential(
        self,
        handle,
        rp,
        user,
        params,
        client_data,
        make_options,
        attestation_pointer,
    ):
        self.last_make_credential_call = {
            "handle": handle,
            "rp": rp,
            "user": user,
            "params": params,
            "client_data": client_data,
            "options": make_options,
            "output": attestation_pointer,
        }
        if self._make_impl:
            return self._make_impl(
                handle,
                rp,
                user,
                params,
                client_data,
                make_options,
                attestation_pointer,
            )
        raise AssertionError("No fake make_credential implementation set")

    def WebAuthNAuthenticatorGetAssertion(
        self,
        handle,
        rp_id,
        client_data,
        get_options,
        assertion_pointer,
    ):
        self.last_get_assertion_call = {
            "handle": handle,
            "rp_id": rp_id,
            "client_data": client_data,
            "options": get_options,
            "output": assertion_pointer,
        }
        if self._get_impl:
            return self._get_impl(
                handle,
                rp_id,
                client_data,
                get_options,
                assertion_pointer,
            )
        raise AssertionError("No fake get_assertion implementation set")


def _build_fake_win_api_module(
    *,
    api_version: int,
    make_impl=None,
    get_impl=None,
):
    module = types.ModuleType("fido2.client.win_api")
    fake_webauthn = _FakeWebAuthnApi()
    fake_webauthn.set_make_impl(make_impl)
    fake_webauthn.set_get_impl(get_impl)

    class GUID:
        pass

    class WebAuthNAttestationConveyancePreference(_FromStringEnum):
        ANY = 0
        NONE = 1
        INDIRECT = 2
        DIRECT = 3

    class WebAuthNAuthenticatorAttachment(_FromStringEnum):
        ANY = 0
        PLATFORM = 1
        CROSS_PLATFORM = 2

    class WebAuthNEnterpriseAttestation(_FromStringEnum):
        NONE = 0
        VENDOR_FACILITATED = 1
        PLATFORM_MANAGED = 2

    class WebAuthNLargeBlobSupport(_FromStringEnum):
        NONE = 0
        REQUIRED = 1
        PREFERRED = 2

    class WebAuthNLargeBlobOperation(_FromStringEnum):
        NONE = 0
        GET = 1
        SET = 2

    class WebAuthNUserVerificationRequirement(_FromStringEnum):
        ANY = 0
        REQUIRED = 1
        PREFERRED = 2
        DISCOURAGED = 3

    class WebAuthNUserVerification(_FromStringEnum):
        ANY = 0
        OPTIONAL = 1
        OPTIONAL_WITH_CREDENTIAL_ID_LIST = 2
        REQUIRED = 3

    class WebAuthNClientData:
        def __init__(self, client_data):
            self.client_data = client_data

    class WebAuthNRpEntityInformation:
        def __init__(self, rp):
            self.rp = rp

    class WebAuthNUserEntityInformation:
        def __init__(self, user):
            self.user = user

    class WebAuthNCoseCredentialParameters:
        def __init__(self, params):
            self.params = params

    class WebAuthNCredProtectExtensionIn:
        def __init__(self, policy, enforce):
            self.policy = policy
            self.enforce = enforce

    class WebAuthNCredBlobExtension:
        def __init__(self, blob):
            self.blob = blob

    class WebAuthNHmacSecretSalt:
        def __init__(self, first, second=None):
            self.first = first
            self.second = second

    class WebAuthNCredWithHmacSecretSalt:
        def __init__(self, cred_id, salt):
            self.cred_id = cred_id
            self.salt = salt

    class WebAuthNHmacSecretSaltValues:
        def __init__(self, global_salt, credential_salts=()):
            self.global_salt = global_salt
            self.credential_salts = list(credential_salts)

    class WebAuthNExtension:
        def __init__(self, identifier, value):
            self.identifier = identifier
            self.value = value

    class WebAuthNMakeCredentialOptions:
        def __init__(self, *args):
            (
                self.timeout,
                self.require_resident_key,
                self.attachment,
                self.uv_requirement,
                self.attestation,
                self.credentials,
                self.cancellation_id,
                self.enterprise_attestation,
                self.large_blob_support,
                self.prefer_resident_key,
                self.enable_prf,
                self.extensions,
                self.hmac_salts,
                self.credential_hints,
            ) = args

    class WebAuthNGetAssertionOptions:
        def __init__(self, *args):
            (
                self.timeout,
                self.attachment,
                self.uv_requirement,
                self.credentials,
                self.cancellation_id,
                self.large_blob_operation,
                self.large_blob,
                self.hmac_secret_salts,
                self.extensions,
                self.flags,
                self.u2f_appid,
                self.u2f_appid_used,
                self.credential_hints,
            ) = args

    class WebAuthNCredentialAttestation:
        pass

    class WebAuthNAssertion:
        pass

    module.BOOL = _FakeBOOL
    module.GUID = GUID
    module.WEBAUTHN = fake_webauthn
    module.WEBAUTHN_API_VERSION = api_version
    module.WebAuthNAssertion = WebAuthNAssertion
    module.WebAuthNAttestationConveyancePreference = (
        WebAuthNAttestationConveyancePreference
    )
    module.WebAuthNAuthenticatorAttachment = WebAuthNAuthenticatorAttachment
    module.WebAuthNClientData = WebAuthNClientData
    module.WebAuthNCoseCredentialParameters = WebAuthNCoseCredentialParameters
    module.WebAuthNCredBlobExtension = WebAuthNCredBlobExtension
    module.WebAuthNCredentialAttestation = WebAuthNCredentialAttestation
    module.WebAuthNCredProtectExtensionIn = WebAuthNCredProtectExtensionIn
    module.WebAuthNCredWithHmacSecretSalt = WebAuthNCredWithHmacSecretSalt
    module.WebAuthNEnterpriseAttestation = WebAuthNEnterpriseAttestation
    module.WebAuthNExtension = WebAuthNExtension
    module.WebAuthNGetAssertionOptions = WebAuthNGetAssertionOptions
    module.WebAuthNHmacSecretSalt = WebAuthNHmacSecretSalt
    module.WebAuthNHmacSecretSaltValues = WebAuthNHmacSecretSaltValues
    module.WebAuthNLargeBlobOperation = WebAuthNLargeBlobOperation
    module.WebAuthNLargeBlobSupport = WebAuthNLargeBlobSupport
    module.WebAuthNMakeCredentialOptions = WebAuthNMakeCredentialOptions
    module.WebAuthNRpEntityInformation = WebAuthNRpEntityInformation
    module.WebAuthNUserEntityInformation = WebAuthNUserEntityInformation
    module.WebAuthNUserVerification = WebAuthNUserVerification
    module.WebAuthNUserVerificationRequirement = WebAuthNUserVerificationRequirement
    module.windll = types.SimpleNamespace(
        user32=types.SimpleNamespace(GetForegroundWindow=lambda: 4242)
    )

    return module, fake_webauthn


def _load_windows_module(
    monkeypatch,
    *,
    api_version: int,
    make_impl=None,
    get_impl=None,
):
    windows_path = _repo_root() / "fido2" / "client" / "windows.py"
    module_name = (
        f"fido2.client._windows_contracts_{api_version}_{id(make_impl)}_{id(get_impl)}"
    )

    fake_win_api_mod, fake_webauthn = _build_fake_win_api_module(
        api_version=api_version,
        make_impl=make_impl,
        get_impl=get_impl,
    )

    monkeypatch.setitem(sys.modules, "fido2.client.win_api", fake_win_api_mod)

    spec = importlib.util.spec_from_file_location(module_name, windows_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "fido2.client"
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module, fake_webauthn, fake_win_api_mod


def _patch_ctypes_boundary(monkeypatch, windows_mod):
    class _Pointer:
        def __init__(self):
            self.contents = None

    monkeypatch.setattr(windows_mod.ctypes, "byref", lambda value: value)
    monkeypatch.setattr(windows_mod.ctypes, "POINTER", lambda _typ: _Pointer)


def _attestation_object_bytes() -> bytes:
    public_key = ES256.from_ctap1(b"\x04" + (b"\x33" * 64))
    cred_data = AttestedCredentialData.create(
        Aaguid.NONE,
        b"cred-id",
        public_key,
    )
    auth_data = AuthenticatorData.create(
        b"\x44" * 32,
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT | AuthenticatorData.FLAG.ED,
        1,
        cred_data,
        {"hmac-secret": True},
    )
    return bytes(AttestationObject.create("none", auth_data, {}))


def _assertion_auth_data_bytes() -> bytes:
    return bytes(
        AuthenticatorData.create(
            b"\x55" * 32,
            AuthenticatorData.FLAG.UP,
            7,
        )
    )


def _creation_options(**overrides):
    kwargs = {
        "rp": {"id": "example.com", "name": "Example RP"},
        "user": {"id": b"user-id", "name": "user", "displayName": "User"},
        "challenge": b"create-challenge",
        "pub_key_cred_params": [{"type": "public-key", "alg": -7}],
        "authenticator_selection": {
            "authenticatorAttachment": "cross-platform",
            "residentKey": "preferred",
            "userVerification": "discouraged",
        },
        "attestation": "none",
        "extensions": None,
    }
    hints = overrides.pop("hints", None)
    kwargs.update(overrides)
    options = PublicKeyCredentialCreationOptions(**kwargs)
    object.__setattr__(options, "hints", hints)
    return options


def _request_options(**overrides):
    kwargs = {
        "challenge": b"assert-challenge",
        "rp_id": "example.com",
        "allow_credentials": [{"type": "public-key", "id": b"allow-cred"}],
        "user_verification": "discouraged",
        "extensions": None,
    }
    hints = overrides.pop("hints", None)
    kwargs.update(overrides)
    options = PublicKeyCredentialRequestOptions(**kwargs)
    object.__setattr__(options, "hints", hints)
    return options


def test_windows_client_is_available_reflects_api_version(monkeypatch):
    unavailable_mod, _, _ = _load_windows_module(monkeypatch, api_version=0)
    available_mod, _, _ = _load_windows_module(monkeypatch, api_version=7)

    assert unavailable_mod.WindowsClient.is_available() is False
    assert available_mod.WindowsClient.is_available() is True


def test_wrap_ext_maps_known_types_and_preserves_unknown(monkeypatch):
    windows_mod, _, _ = _load_windows_module(monkeypatch, api_version=7)

    wrapped = windows_mod._wrap_ext(
        "prf",
        {
            "enabled": True,
            "results": {"first": b"a" * 32, "second": b"b" * 32},
        },
    )
    assert isinstance(wrapped, AuthenticatorExtensionsPRFOutputs)
    assert wrapped.enabled is True
    assert wrapped.results is not None
    assert wrapped.results.first == b"a" * 32
    assert wrapped.results.second == b"b" * 32

    value = {"raw": "value"}
    assert windows_mod._wrap_ext("not-registered", value) is value


def test_cancel_thread_cancels_only_when_not_completed(monkeypatch):
    windows_mod, fake_webauthn, _ = _load_windows_module(monkeypatch, api_version=7)
    monkeypatch.setattr(windows_mod.ctypes, "byref", lambda value: value)

    event = Event()
    event.set()
    timer = windows_mod.CancelThread(event)
    timer.run()

    assert fake_webauthn.get_cancellation_id_calls == 1
    assert fake_webauthn.cancel_current_calls == 1

    event2 = Event()
    timer2 = windows_mod.CancelThread(event2)
    joined = {"count": 0}
    monkeypatch.setattr(
        timer2,
        "join",
        lambda: joined.__setitem__("count", joined["count"] + 1),
    )
    timer2.complete()
    timer2.run()

    assert joined["count"] == 1
    assert fake_webauthn.cancel_current_calls == 1


def test_make_credential_enterprise_prf_and_extension_outputs(monkeypatch):
    captured = {}

    def _make_impl(_handle, _rp, _user, _params, _client_data, make_options, out_ptr):
        captured["options"] = make_options
        out_ptr.contents = types.SimpleNamespace(
            attestation_object=_attestation_object_bytes(),
            dwVersion=7,
            bResidentKey=True,
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"prf-first", second=b"prf-second")
            ),
            bLargeBlobSupported=True,
        )

    windows_mod, _fake_webauthn, win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        make_impl=_make_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)
    _FakeCancelThread.instances = []
    monkeypatch.setattr(windows_mod, "CancelThread", _FakeCancelThread)

    client = windows_mod.WindowsClient(_Collector())
    client._enterprise_rpid_list = ["example.com"]

    options = _creation_options(
        attestation="enterprise",
        extensions={
            "credProps": True,
            "largeBlob": {"support": "preferred"},
            "prf": {"eval": {"first": b"A" * 32, "second": b"B" * 32}},
        },
        hints=["security-key"],
    )

    result = client.make_credential(options, event=Event())

    make_opts = captured["options"]
    assert make_opts.enterprise_attestation == win_api_mod.WebAuthNEnterpriseAttestation.PLATFORM_MANAGED
    assert make_opts.large_blob_support == win_api_mod.WebAuthNLargeBlobSupport.PREFERRED
    assert make_opts.enable_prf is True
    assert make_opts.hmac_salts.first == b"A" * 32
    assert make_opts.hmac_salts.second == b"B" * 32
    assert {ext.identifier for ext in make_opts.extensions} == {"minPinLength", "hmac-secret"}

    timer = _FakeCancelThread.instances[-1]
    assert timer.started is True
    assert timer.completed is True

    assert result.id == b"cred-id"
    ext = result.client_extension_results
    assert isinstance(ext.prf, AuthenticatorExtensionsPRFOutputs)
    assert ext.prf.enabled is True
    assert ext.prf.results is not None
    assert ext.prf.results.first == b"prf-first"
    assert ext.prf.results.second == b"prf-second"
    assert isinstance(ext.cred_props, CredentialPropertiesOutput)
    assert ext.cred_props.rk is True
    assert isinstance(ext.large_blob, AuthenticatorExtensionsLargeBlobOutputs)
    assert ext.large_blob.supported is True


def test_make_credential_hmac_secret_vendor_attestation_output(monkeypatch):
    captured = {}

    def _make_impl(_handle, _rp, _user, _params, _client_data, make_options, out_ptr):
        captured["options"] = make_options
        out_ptr.contents = types.SimpleNamespace(
            attestation_object=_attestation_object_bytes(),
            dwVersion=7,
            bResidentKey=False,
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"secret-one", second=b"")
            ),
            bLargeBlobSupported=False,
        )

    windows_mod, _fake_webauthn, win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        make_impl=_make_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector(), allow_hmac_secret=True)

    options = _creation_options(
        attestation="enterprise",
        extensions={
            "hmacCreateSecret": True,
            "hmacGetSecret": {"salt1": b"S" * 32, "salt2": b"T" * 32},
        },
        hints=[],
    )

    result = client.make_credential(options)

    make_opts = captured["options"]
    assert make_opts.enterprise_attestation == win_api_mod.WebAuthNEnterpriseAttestation.VENDOR_FACILITATED
    assert make_opts.enable_prf is False
    assert make_opts.hmac_salts.first == b"S" * 32
    assert make_opts.hmac_salts.second == b"T" * 32

    ext = result.client_extension_results
    assert ext.hmac_create_secret is True
    assert isinstance(ext.hmac_get_secret, HMACGetSecretOutput)
    assert ext.hmac_get_secret.output1 == b"secret-one"
    assert ext.hmac_get_secret.output2 is None


def test_make_credential_maps_oserror_to_client_error(monkeypatch):
    def _make_impl(*_args, **_kwargs):
        raise OSError("make failed")

    windows_mod, _, _ = _load_windows_module(
        monkeypatch,
        api_version=9,
        make_impl=_make_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector())

    with pytest.raises(ClientError) as err:
        client.make_credential(_creation_options(hints=[]))

    assert err.value.code == ClientError.ERR.OTHER_ERROR
    assert isinstance(err.value.cause, OSError)


def test_get_assertion_prf_appid_and_large_blob_read_outputs(monkeypatch):
    captured = {}

    def _get_impl(_handle, _rp_id, _client_data, get_options, out_ptr):
        captured["options"] = get_options
        get_options.u2f_appid_used.value = True
        out_ptr.contents = types.SimpleNamespace(
            dwVersion=3,
            auth_data=_assertion_auth_data_bytes(),
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"prf-one", second=b"prf-two")
            ),
            dwCredLargeBlobStatus=1,
            cred_large_blob=b"blob-read",
            Credential=types.SimpleNamespace(
                pwszCredentialType="public-key",
                id=b"assert-id",
            ),
            signature=b"signature",
            user_id=b"user-id",
        )

    windows_mod, _fake_webauthn, win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        get_impl=_get_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector())

    encoded_allow_cred = websafe_encode(b"allow-cred")
    options = _request_options(
        extensions={
            "appid": "https://u2f.example",
            "largeBlob": {"read": True},
            "prf": {
                "eval": {"first": b"P" * 32, "second": b"Q" * 32},
                "evalByCredential": {encoded_allow_cred: {"first": b"R" * 32}},
            },
        },
        hints=["unknown", "client-device"],
    )

    selection = client.get_assertion(options)

    get_opts = captured["options"]
    assert get_opts.attachment == win_api_mod.WebAuthNAuthenticatorAttachment.PLATFORM
    assert get_opts.large_blob_operation == win_api_mod.WebAuthNLargeBlobOperation.GET
    assert get_opts.u2f_appid == "https://u2f.example"
    assert len(get_opts.hmac_secret_salts.credential_salts) == 1

    response = selection.get_response(0)
    assert response.id == b"assert-id"
    assert response.response.user_handle == b"user-id"

    ext = response.client_extension_results
    assert ext.appid is True
    assert isinstance(ext.prf, AuthenticatorExtensionsPRFOutputs)
    assert ext.prf.results is not None
    assert ext.prf.results.first == b"prf-one"
    assert ext.prf.results.second == b"prf-two"
    assert isinstance(ext.large_blob, AuthenticatorExtensionsLargeBlobOutputs)
    assert ext.large_blob.blob == b"blob-read"


def test_get_assertion_hmac_secret_write_branch_and_timer(monkeypatch):
    captured = {}

    def _get_impl(_handle, _rp_id, _client_data, get_options, out_ptr):
        captured["options"] = get_options
        out_ptr.contents = types.SimpleNamespace(
            dwVersion=3,
            auth_data=_assertion_auth_data_bytes(),
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"hmac-one", second=b"")
            ),
            dwCredLargeBlobStatus=1,
            cred_large_blob=b"",
            Credential=types.SimpleNamespace(
                pwszCredentialType="public-key",
                id=b"assert-id",
            ),
            signature=b"signature",
            user_id=b"",
        )

    windows_mod, _fake_webauthn, win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        get_impl=_get_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)
    _FakeCancelThread.instances = []
    monkeypatch.setattr(windows_mod, "CancelThread", _FakeCancelThread)

    client = windows_mod.WindowsClient(_Collector(), allow_hmac_secret=True)

    options = _request_options(
        extensions={
            "hmacGetSecret": {"salt1": b"X" * 32, "salt2": b"Y" * 32},
            "largeBlob": {"write": b"blob-payload"},
        },
        hints=["unknown", "security-key"],
    )

    selection = client.get_assertion(options, event=Event())

    get_opts = captured["options"]
    assert get_opts.attachment == win_api_mod.WebAuthNAuthenticatorAttachment.CROSS_PLATFORM
    assert get_opts.flags == 0x00100000
    assert get_opts.large_blob_operation == win_api_mod.WebAuthNLargeBlobOperation.SET
    assert get_opts.hmac_secret_salts is not None

    timer = _FakeCancelThread.instances[-1]
    assert timer.started is True
    assert timer.completed is True

    response = selection.get_response(0)
    assert response.response.user_handle is None

    ext = response.client_extension_results
    assert isinstance(ext.hmac_get_secret, HMACGetSecretOutput)
    assert ext.hmac_get_secret.output1 == b"hmac-one"
    assert ext.hmac_get_secret.output2 is None
    assert isinstance(ext.large_blob, AuthenticatorExtensionsLargeBlobOutputs)
    assert ext.large_blob.written is True


def test_get_assertion_maps_oserror_to_client_error(monkeypatch):
    def _get_impl(*_args, **_kwargs):
        raise OSError("get failed")

    windows_mod, _, _ = _load_windows_module(
        monkeypatch,
        api_version=9,
        get_impl=_get_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector())

    with pytest.raises(ClientError) as err:
        client.get_assertion(_request_options(hints=[]))

    assert err.value.code == ClientError.ERR.OTHER_ERROR
    assert isinstance(err.value.cause, OSError)


def test_make_credential_credprotect_credblob_and_pre_v7_hmac_outputs(monkeypatch):
    captured = {}

    def _make_impl(_handle, _rp, _user, _params, _client_data, make_options, out_ptr):
        captured["options"] = make_options
        out_ptr.contents = types.SimpleNamespace(
            attestation_object=_attestation_object_bytes(),
            dwVersion=6,
            bResidentKey=False,
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"first", second=b"second")
            ),
            bLargeBlobSupported=False,
        )

    windows_mod, _fake_webauthn, _win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        make_impl=_make_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector(), allow_hmac_secret=True)

    options = _creation_options(
        attestation="none",
        extensions={
            "credentialProtectionPolicy": "required",
            "enforceCredentialProtectionPolicy": True,
            "credBlob": b"cred-blob",
            "minPinLength": False,
            "hmacCreateSecret": True,
            "hmacGetSecret": {"salt1": b"S" * 32, "salt2": b"T" * 32},
        },
        hints=[],
    )

    response = client.make_credential(options)

    extension_ids = {ext.identifier for ext in captured["options"].extensions}
    assert extension_ids == {"credProtect", "credBlob", "hmac-secret"}

    ext = response.client_extension_results
    assert ext.hmac_create_secret is True
    # Version 6 does not expose pHmacSecret outputs from the platform.
    assert ext.hmac_get_secret is None


def test_make_credential_hmac_get_secret_includes_second_output_for_version7(monkeypatch):
    def _make_impl(_handle, _rp, _user, _params, _client_data, _make_options, out_ptr):
        out_ptr.contents = types.SimpleNamespace(
            attestation_object=_attestation_object_bytes(),
            dwVersion=7,
            bResidentKey=False,
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"secret-one", second=b"secret-two")
            ),
            bLargeBlobSupported=False,
        )

    windows_mod, _fake_webauthn, _win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        make_impl=_make_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector(), allow_hmac_secret=True)
    response = client.make_credential(
        _creation_options(
            attestation="none",
            extensions={
                "hmacCreateSecret": True,
                "hmacGetSecret": {"salt1": b"U" * 32, "salt2": b"V" * 32},
            },
            hints=[],
        )
    )

    ext = response.client_extension_results
    assert isinstance(ext.hmac_get_secret, HMACGetSecretOutput)
    assert ext.hmac_get_secret.output1 == b"secret-one"
    assert ext.hmac_get_secret.output2 == b"secret-two"


def test_get_assertion_includes_getcredblob_extension_and_hmac_second_output(monkeypatch):
    captured = {}

    def _get_impl(_handle, _rp_id, _client_data, get_options, out_ptr):
        captured["options"] = get_options
        out_ptr.contents = types.SimpleNamespace(
            dwVersion=3,
            auth_data=_assertion_auth_data_bytes(),
            pHmacSecret=types.SimpleNamespace(
                contents=types.SimpleNamespace(first=b"hmac-one", second=b"hmac-two")
            ),
            dwCredLargeBlobStatus=0,
            cred_large_blob=b"",
            Credential=types.SimpleNamespace(
                pwszCredentialType="public-key",
                id=b"assert-id",
            ),
            signature=b"signature",
            user_id=b"",
        )

    windows_mod, _fake_webauthn, _win_api_mod = _load_windows_module(
        monkeypatch,
        api_version=9,
        get_impl=_get_impl,
    )
    _patch_ctypes_boundary(monkeypatch, windows_mod)

    client = windows_mod.WindowsClient(_Collector(), allow_hmac_secret=True)
    selection = client.get_assertion(
        _request_options(
            extensions={
                "getCredBlob": True,
                "hmacGetSecret": {"salt1": b"X" * 32, "salt2": b"Y" * 32},
            },
            hints=[],
        )
    )

    assert {ext.identifier for ext in captured["options"].extensions} == {"credBlob"}

    response = selection.get_response(0)
    ext = response.client_extension_results
    assert isinstance(ext.hmac_get_secret, HMACGetSecretOutput)
    assert ext.hmac_get_secret.output1 == b"hmac-one"
    assert ext.hmac_get_secret.output2 == b"hmac-two"
