from __future__ import annotations

import ctypes
import importlib.util
import sys
from pathlib import Path

import pytest


def _load_win_api_module(monkeypatch, *, api_version: int = 9):
    win_api_path = Path(__file__).resolve().parents[2] / "fido2" / "client" / "win_api.py"
    module_name = f"fido2.client._win_api_contracts_{api_version}_{id(monkeypatch)}"

    class _FakeFunction:
        def __init__(self, return_value=0):
            self.return_value = return_value
            self.argtypes = None
            self.restype = None
            self.calls = []

        def __call__(self, *args):
            self.calls.append(args)
            return self.return_value

    class _FakeLib:
        def __init__(self):
            self._functions = {}

        def __getattr__(self, name):
            if name not in self._functions:
                rv = api_version if name == "WebAuthNGetApiVersionNumber" else 0
                self._functions[name] = _FakeFunction(rv)
            return self._functions[name]

    class _FakeLoader:
        def __init__(self, _dll_factory):
            self._libs = {}

        def __getattr__(self, name):
            if name not in self._libs:
                self._libs[name] = _FakeLib()
            return self._libs[name]

    monkeypatch.setattr(ctypes, "WinDLL", lambda _name: None, raising=False)
    monkeypatch.setattr(ctypes, "LibraryLoader", _FakeLoader, raising=False)
    monkeypatch.setattr(ctypes, "HRESULT", ctypes.c_long, raising=False)

    spec = importlib.util.spec_from_file_location(module_name, win_api_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "fido2.client"
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_win_api_bytes_property_structs_and_guid_rendering(monkeypatch):
    module = _load_win_api_module(monkeypatch, api_version=9)

    client_data = module.WebAuthNClientData(b"client-json")
    assert client_data.client_data_json == b"client-json"
    assert client_data.pwszHashAlgId == "SHA-256"

    rp_info = module.WebAuthNRpEntityInformation({"id": "example.com", "name": "Example"})
    assert rp_info.pwszId == "example.com"
    assert rp_info.pwszName == "Example"

    user_info = module.WebAuthNUserEntityInformation(
        {"id": b"user-id", "name": "alice", "displayName": "Alice"}
    )
    assert user_info.id == b"user-id"
    assert user_info.pwszName == "alice"
    assert user_info.pwszDisplayName == "Alice"

    guid = module.GUID()
    guid.Data1 = 0xAABBCCDD
    guid.Data2 = 0xEEFF
    guid.Data3 = 0x1122
    guid.Data4[:] = (0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA)

    assert str(guid) == "{AABBCCDD-EEFF-1122-3344-5566778899AA}"


def test_win_api_enum_from_string_and_get_version_contracts(monkeypatch):
    module = _load_win_api_module(monkeypatch, api_version=9)

    assert (
        module.WebAuthNAuthenticatorAttachment.from_string("cross-platform")
        == module.WebAuthNAuthenticatorAttachment.CROSS_PLATFORM
    )
    assert (
        module.WebAuthNUserVerificationRequirement.from_string("discouraged")
        == module.WebAuthNUserVerificationRequirement.DISCOURAGED
    )

    assert module.get_version("WebAuthNClientData") >= 1

    with pytest.raises(ValueError, match="Unknown class name"):
        module.get_version("NotARealStruct")


def test_win_api_make_and_get_option_structs_populate_high_version_fields(monkeypatch):
    module = _load_win_api_module(monkeypatch, api_version=9)

    global_salt = module.WebAuthNHmacSecretSalt(b"A" * 32, b"B" * 32)
    per_cred = module.WebAuthNCredWithHmacSecretSalt(b"cred-1", global_salt)
    salt_values = module.WebAuthNHmacSecretSaltValues(global_salt, [per_cred])

    extension = module.WebAuthNExtension("hmac-secret", module.WebAuthNCredBlobExtension(b"blob"))

    get_opts = module.WebAuthNGetAssertionOptions(
        timeout=1500,
        attachment=module.WebAuthNAuthenticatorAttachment.PLATFORM,
        uv_requirement=module.WebAuthNUserVerificationRequirement.PREFERRED,
        credentials=[{"type": "public-key", "id": b"cred"}],
        cancellationId=module.GUID(),
        cred_large_blob_operation=module.WebAuthNLargeBlobOperation.GET,
        cred_large_blob=b"blob-data",
        hmac_secret_salts=salt_values,
        extensions=[extension],
        flags=7,
        u2f_appid="https://u2f.example",
        u2f_appid_used=module.BOOL(),
        credential_hints=["security-key"],
        remote_web_origin="https://example.com",
        public_key_credential_request_options_json=b"{}",
        authenticator_id=b"auth-id",
    )

    assert get_opts.dwVersion == module.get_version("WebAuthNGetAssertionOptions")
    assert get_opts.dwTimeoutMilliseconds == 1500
    assert get_opts.dwCredLargeBlobOperation == module.WebAuthNLargeBlobOperation.GET
    assert get_opts.cred_large_blob == b"blob-data"
    assert get_opts.pwszRemoteWebOrigin == "https://example.com"
    assert get_opts.authenticator_id == b"auth-id"

    make_opts = module.WebAuthNMakeCredentialOptions(
        timeout=1200,
        require_resident_key=True,
        attachment=module.WebAuthNAuthenticatorAttachment.CROSS_PLATFORM,
        uv_requirement=module.WebAuthNUserVerificationRequirement.REQUIRED,
        attestation_convoyence=module.WebAuthNAttestationConveyancePreference.DIRECT,
        credentials=[{"type": "public-key", "id": b"cred"}],
        cancellationId=module.GUID(),
        enterprise_attestation=module.WebAuthNEnterpriseAttestation.PLATFORM_MANAGED,
        large_blob_support=module.WebAuthNLargeBlobSupport.PREFERRED,
        prefer_resident_key=True,
        enable_prf=True,
        extensions=[extension],
        prf_global_eval=global_salt,
        credential_hints=["client-device"],
        third_party_payment=True,
        remote_web_origin="https://merchant.example",
        public_key_credential_creation_options_json=b"{\"rp\":{}}",
        authenticator_id=b"authenticator",
    )

    assert make_opts.dwVersion == module.get_version("WebAuthNMakeCredentialOptions")
    assert make_opts.dwTimeoutMilliseconds == 1200
    assert make_opts.dwEnterpriseAttestation == module.WebAuthNEnterpriseAttestation.PLATFORM_MANAGED
    assert make_opts.dwLargeBlobSupport == module.WebAuthNLargeBlobSupport.PREFERRED
    assert bool(make_opts.bEnablePrf) is True
    assert make_opts.pwszRemoteWebOrigin == "https://merchant.example"
    assert make_opts.authenticator_id == b"authenticator"


def test_win_api_credentials_and_extensions_container_shapes(monkeypatch):
    module = _load_win_api_module(monkeypatch, api_version=9)

    credential = module.WebAuthNCredential({"id": b"cred-id", "type": "public-key"})
    assert credential.id == b"cred-id"

    credentials = module.WebAuthNCredentials(
        [{"id": b"cred-1", "type": "public-key"}, {"id": b"cred-2", "type": "public-key"}]
    )
    assert credentials.cCredentials == 2

    cose_params = module.WebAuthNCoseCredentialParameters(
        [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}]
    )
    assert cose_params.cCredentialParameters == 2

    ext_a = module.WebAuthNExtension("credBlob", module.WebAuthNCredBlobExtension(b"blob-a"))
    ext_b = module.WebAuthNExtension(
        "credProtect",
        module.WebAuthNCredProtectExtensionIn(module.WebAuthNUserVerification.REQUIRED, True),
    )
    exts = module.WebAuthNExtensions([ext_a, ext_b])
    assert exts.cExtensions == 2


def test_win_api_assertion_and_attestation_destructors_call_webauthn_free(monkeypatch):
    module = _load_win_api_module(monkeypatch, api_version=9)

    assertion = module.WebAuthNAssertion()
    attestation = module.WebAuthNCredentialAttestation()

    free_assertion = module.WEBAUTHN.WebAuthNFreeAssertion
    free_attestation = module.WEBAUTHN.WebAuthNFreeCredentialAttestation

    assertion.__del__()
    attestation.__del__()

    assert len(free_assertion.calls) == 1
    assert len(free_attestation.calls) == 1
