from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature

import fido2.server as server_module
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestationConveyancePreference,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)


class _FakeClientData(bytes):
    def __new__(
        cls,
        payload=b"client-data-json",
        *,
        type_value,
        origin,
        challenge,
        hash_value=b"hash-default",
        get_hash_value=b"hash-alt",
    ):
        obj = bytes.__new__(cls, payload)
        obj.type = type_value
        obj.origin = origin
        obj.challenge = challenge
        obj.hash = hash_value
        obj._get_hash_value = get_hash_value
        return obj

    def get_hash(self, _algorithm):
        return self._get_hash_value


class _FakeAuthData(bytes):
    def __new__(
        cls,
        payload=b"auth-data-bytes",
        *,
        rp_id_hash,
        user_present=True,
        user_verified=True,
        credential_id=b"cred-id",
    ):
        obj = bytes.__new__(cls, payload)
        obj.rp_id_hash = rp_id_hash
        obj._user_present = user_present
        obj._user_verified = user_verified
        obj.credential_data = SimpleNamespace(credential_id=credential_id)
        return obj

    def is_user_present(self):
        return self._user_present

    def is_user_verified(self):
        return self._user_verified


class _PublicKey:
    def __init__(self, *, raise_invalid=False):
        self.raise_invalid = raise_invalid
        self.verify_calls = []
        self.debug_calls = []

    def set_assertion_debug_data(self, auth_data, client_data):
        self.debug_calls.append((auth_data, client_data))

    def verify(self, data, signature):
        self.verify_calls.append((data, signature))
        if self.raise_invalid:
            raise CryptoInvalidSignature()


def _make_server(verify_origin=None, attestation=None, verify_attestation=None):
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    return server_module.Fido2Server(
        rp,
        attestation=attestation,
        verify_origin=verify_origin,
        verify_attestation=verify_attestation,
    )


def test_validata_challenge_and_register_begin_guardrails():
    with pytest.raises(TypeError, match="Custom challenge must be of type 'bytes'"):
        server_module._validata_challenge("not-bytes")

    with pytest.raises(ValueError, match="length must be >= 16"):
        server_module._validata_challenge(b"short")

    server = _make_server(verify_origin=lambda _origin: True)
    server.allowed_algorithms = []
    with pytest.raises(ValueError, match="no allowed algorithms"):
        server.register_begin(
            PublicKeyCredentialUserEntity(
                id=b"user-id",
                name="user@example.com",
                display_name="User",
            )
        )


def test_register_complete_response_parsing_validation_and_attestation_callback(monkeypatch):
    challenge = b"A" * 16
    server = _make_server(verify_origin=lambda origin: origin == "https://ok.example")
    state = server._make_internal_state(challenge, None)

    good_client_data = _FakeClientData(
        type_value=CollectedClientData.TYPE.CREATE,
        origin="https://ok.example",
        challenge=challenge,
        hash_value=b"client-hash",
    )
    good_auth_data = _FakeAuthData(rp_id_hash=server.rp.id_hash)
    good_attestation = SimpleNamespace(auth_data=good_auth_data, fmt="packed")

    registration = SimpleNamespace(
        response=SimpleNamespace(
            client_data=good_client_data,
            attestation_object=good_attestation,
        )
    )
    monkeypatch.setattr(
        server_module.RegistrationResponse,
        "from_dict",
        classmethod(lambda _cls, _response: registration),
    )

    assert server.register_complete(state, {"dummy": True}) is good_auth_data
    assert server.register_complete(state, response={"dummy": True}) is good_auth_data

    with pytest.raises(TypeError, match="incorrect arguments"):
        server.register_complete(
            state,
            good_client_data,
            client_data=good_client_data,
            attestation_object=good_attestation,
        )

    with pytest.raises(ValueError, match="Incorrect type"):
        server.register_complete(
            state,
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.GET,
                origin="https://ok.example",
                challenge=challenge,
            ),
            attestation_object=good_attestation,
        )

    with pytest.raises(ValueError, match="Invalid origin"):
        server.register_complete(
            state,
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.CREATE,
                origin="https://bad.example",
                challenge=challenge,
            ),
            attestation_object=good_attestation,
        )

    with pytest.raises(ValueError, match="Wrong challenge"):
        server.register_complete(
            state,
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.CREATE,
                origin="https://ok.example",
                challenge=b"B" * 16,
            ),
            attestation_object=good_attestation,
        )

    with pytest.raises(ValueError, match="Wrong RP ID hash"):
        server.register_complete(
            state,
            client_data=good_client_data,
            attestation_object=SimpleNamespace(
                auth_data=_FakeAuthData(rp_id_hash=b"wrong-rp-hash"),
                fmt="packed",
            ),
        )

    with pytest.raises(ValueError, match="User Present flag not set"):
        server.register_complete(
            state,
            client_data=good_client_data,
            attestation_object=SimpleNamespace(
                auth_data=_FakeAuthData(rp_id_hash=server.rp.id_hash, user_present=False),
                fmt="packed",
            ),
        )

    state_uv = server._make_internal_state(challenge, UserVerificationRequirement.REQUIRED)
    with pytest.raises(ValueError, match="User verification required"):
        server.register_complete(
            state_uv,
            client_data=good_client_data,
            attestation_object=SimpleNamespace(
                auth_data=_FakeAuthData(rp_id_hash=server.rp.id_hash, user_verified=False),
                fmt="packed",
            ),
        )

    attestation_calls = []
    attestation_server = _make_server(
        verify_origin=lambda _origin: True,
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=lambda att_obj, client_hash: attestation_calls.append(
            (att_obj, client_hash)
        ),
    )
    attestation_state = attestation_server._make_internal_state(challenge, None)
    att_client_data = _FakeClientData(
        type_value=CollectedClientData.TYPE.CREATE,
        origin="https://anything.example",
        challenge=challenge,
        hash_value=b"att-hash",
    )
    att_auth_data = _FakeAuthData(rp_id_hash=attestation_server.rp.id_hash)
    att_attestation = SimpleNamespace(auth_data=att_auth_data, fmt="packed")

    assert (
        attestation_server.register_complete(
            attestation_state,
            client_data=att_client_data,
            attestation_object=att_attestation,
        )
        is att_auth_data
    )
    assert attestation_calls == [(att_attestation, b"att-hash")]


def test_authenticate_complete_response_parsing_validation_and_signature_paths(monkeypatch):
    challenge = b"C" * 16
    server = _make_server(verify_origin=lambda origin: origin == "https://ok.example")
    state = {"challenge": websafe_encode(challenge), "user_verification": None}

    good_client_data = _FakeClientData(
        type_value=CollectedClientData.TYPE.GET,
        origin="https://ok.example",
        challenge=challenge,
        hash_value=b"client-hash-default",
        get_hash_value=b"client-hash-alt",
    )
    good_auth_data = _FakeAuthData(rp_id_hash=server.rp.id_hash)
    pub = _PublicKey()
    cred = SimpleNamespace(credential_id=b"cred-1", public_key=pub)

    result = server.authenticate_complete(
        state,
        [cred],
        credential_id=b"cred-1",
        client_data=good_client_data,
        auth_data=good_auth_data,
        signature=b"sig",
        hash_algorithm="SHA-512",
    )
    assert result is cred
    assert pub.debug_calls == [(bytes(good_auth_data), bytes(good_client_data))]
    assert pub.verify_calls == [(bytes(good_auth_data) + b"client-hash-alt", b"sig")]

    authentication = SimpleNamespace(
        id=b"cred-1",
        response=SimpleNamespace(
            client_data=good_client_data,
            authenticator_data=good_auth_data,
            signature=b"sig",
        ),
    )
    monkeypatch.setattr(
        server_module.AuthenticationResponse,
        "from_dict",
        classmethod(lambda _cls, _response: authentication),
    )
    assert server.authenticate_complete(state, [cred], response={"dummy": True}) is cred

    with pytest.raises(TypeError, match="incorrect arguments"):
        server.authenticate_complete(state, [cred], credential_id=b"cred-1")

    with pytest.raises(ValueError, match="Incorrect type"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"cred-1",
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.CREATE,
                origin="https://ok.example",
                challenge=challenge,
            ),
            auth_data=good_auth_data,
            signature=b"sig",
        )

    with pytest.raises(ValueError, match="Invalid origin"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"cred-1",
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.GET,
                origin="https://bad.example",
                challenge=challenge,
            ),
            auth_data=good_auth_data,
            signature=b"sig",
        )

    with pytest.raises(ValueError, match="Wrong challenge"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"cred-1",
            client_data=_FakeClientData(
                type_value=CollectedClientData.TYPE.GET,
                origin="https://ok.example",
                challenge=b"D" * 16,
            ),
            auth_data=good_auth_data,
            signature=b"sig",
        )

    with pytest.raises(ValueError, match="Wrong RP ID hash"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"cred-1",
            client_data=good_client_data,
            auth_data=_FakeAuthData(rp_id_hash=b"wrong-rp-hash"),
            signature=b"sig",
        )

    with pytest.raises(ValueError, match="User Present flag not set"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"cred-1",
            client_data=good_client_data,
            auth_data=_FakeAuthData(rp_id_hash=server.rp.id_hash, user_present=False),
            signature=b"sig",
        )

    state_uv = {"challenge": websafe_encode(challenge), "user_verification": UserVerificationRequirement.REQUIRED}
    with pytest.raises(ValueError, match="user verified flag not set"):
        server.authenticate_complete(
            state_uv,
            [cred],
            credential_id=b"cred-1",
            client_data=good_client_data,
            auth_data=_FakeAuthData(rp_id_hash=server.rp.id_hash, user_verified=False),
            signature=b"sig",
        )

    bad_pub = _PublicKey(raise_invalid=True)
    bad_cred = SimpleNamespace(credential_id=b"cred-2", public_key=bad_pub)
    with pytest.raises(ValueError, match="Invalid signature"):
        server.authenticate_complete(
            state,
            [bad_cred],
            credential_id=b"cred-2",
            client_data=good_client_data,
            auth_data=good_auth_data,
            signature=b"sig",
        )

    with pytest.raises(ValueError, match="Unknown credential ID"):
        server.authenticate_complete(
            state,
            [cred],
            credential_id=b"unknown",
            client_data=good_client_data,
            auth_data=good_auth_data,
            signature=b"sig",
        )

    class _NoDebugPublicKey:
        def __init__(self):
            self.verify_calls = []

        def verify(self, data, signature):
            self.verify_calls.append((data, signature))

    no_debug_pub = _NoDebugPublicKey()
    no_debug_cred = SimpleNamespace(credential_id=b"cred-3", public_key=no_debug_pub)
    assert (
        server.authenticate_complete(
            state,
            [no_debug_cred],
            credential_id=b"cred-3",
            client_data=good_client_data,
            auth_data=good_auth_data,
            signature=b"sig",
        )
        is no_debug_cred
    )
    assert no_debug_pub.verify_calls == [
        (bytes(good_auth_data) + b"client-hash-default", b"sig")
    ]


def test_authenticate_begin_without_credentials_emits_empty_allow_list_path():
    server = _make_server(verify_origin=lambda _origin: True)

    request, state = server.authenticate_begin(credentials=None, challenge=b"D" * 16)

    assert request.public_key.allow_credentials is None
    assert state["challenge"] == websafe_encode(b"D" * 16)


def test_verify_app_id_and_u2f_server_wrappers_and_fallback(monkeypatch):
    monkeypatch.setattr(
        server_module,
        "verify_rp_id",
        lambda hostname, origin: (hostname, origin)
        in {
            ("app.example", "https://origin.example"),
            ("localhost", "http://localhost"),
        },
    )

    assert server_module.verify_app_id("ftp://app.example", "https://origin.example") is False
    assert server_module.verify_app_id("https://", "https://origin.example") is False
    assert server_module.verify_app_id("https://app.example", "https://origin.example") is True
    assert server_module.verify_app_id("http://localhost", "http://localhost") is True

    init_calls = []

    def _fake_server_init(self, rp, *args, **kwargs):
        init_calls.append((rp, dict(kwargs)))

    monkeypatch.setattr(server_module.Fido2Server, "__init__", _fake_server_init)

    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    custom_verify = lambda _origin: True
    u2f_custom = server_module.U2FFido2Server(
        "https://app.example",
        rp,
        verify_u2f_origin=custom_verify,
    )
    assert u2f_custom._app_id == "https://app.example"
    assert init_calls[1][1]["verify_origin"] is custom_verify

    init_calls.clear()
    monkeypatch.setattr(
        server_module,
        "verify_app_id",
        lambda app_id, origin: app_id == "https://app.example" and origin == "https://origin.example",
    )
    server_module.U2FFido2Server("https://app.example", rp)
    default_verify = init_calls[1][1]["verify_origin"]
    assert default_verify("https://origin.example") is True

    wrapper = object.__new__(server_module.U2FFido2Server)
    wrapper._app_id = "https://app.example"
    wrapper._app_id_server = SimpleNamespace(
        authenticate_complete=lambda *_args, **_kwargs: "fallback-auth"
    )

    monkeypatch.setattr(
        server_module.Fido2Server,
        "register_begin",
        lambda _self, *args, **kwargs: (kwargs.get("extensions"), {"state": "register"}),
    )
    monkeypatch.setattr(
        server_module.Fido2Server,
        "authenticate_begin",
        lambda _self, *args, **kwargs: (kwargs.get("extensions"), {"state": "auth"}),
    )

    reg_request, _reg_state = server_module.U2FFido2Server.register_begin(wrapper)
    auth_request, _auth_state = server_module.U2FFido2Server.authenticate_begin(wrapper)
    assert reg_request["appidExclude"] == "https://app.example"
    assert auth_request["appid"] == "https://app.example"

    monkeypatch.setattr(
        server_module.Fido2Server,
        "authenticate_complete",
        lambda _self, *_args, **_kwargs: (_ for _ in ()).throw(ValueError("primary failed")),
    )
    assert (
        server_module.U2FFido2Server.authenticate_complete(wrapper, "state", [])
        == "fallback-auth"
    )