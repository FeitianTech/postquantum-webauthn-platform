from __future__ import annotations

import types
from unittest import mock

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fido2 import cbor
from fido2.ctap import CtapError
import fido2.ctap2.base as base_module
from fido2.webauthn import AuthenticatorData


def _bare_ctap(device_call, *, strict_cbor=True, max_msg_size=1024, options=None):
    ctap = object.__new__(base_module.Ctap2)
    ctap.device = types.SimpleNamespace(call=device_call)
    ctap._strict_cbor = strict_cbor
    ctap._max_msg_size = max_msg_size
    ctap._info = types.SimpleNamespace(options=options or {}, max_msg_size=max_msg_size)
    return ctap


def test_send_cbor_error_and_edge_paths():
    ctap_too_large = _bare_ctap(lambda *_args: b"\x00", max_msg_size=0)
    with pytest.raises(CtapError):
        ctap_too_large.send_cbor(0x04)

    ctap_status_error = _bare_ctap(lambda *_args: b"\x01")
    with pytest.raises(CtapError):
        ctap_status_error.send_cbor(0x04)

    ctap_empty_payload = _bare_ctap(lambda *_args: b"\x00")
    assert ctap_empty_payload.send_cbor(0x04) == {}

    non_canonical = bytes.fromhex("A2616201616102")
    ctap_strict = _bare_ctap(lambda *_args: b"\x00" + non_canonical, strict_cbor=True)
    with pytest.raises(ValueError, match="Non-canonical CBOR"):
        ctap_strict.send_cbor(0x04)

    ctap_non_strict = _bare_ctap(lambda *_args: b"\x00" + non_canonical, strict_cbor=False)
    assert ctap_non_strict.send_cbor(0x04) == {"b": 1, "a": 2}

    ctap_wrong_type = _bare_ctap(lambda *_args: b"\x00" + cbor.encode([1, 2]))
    with pytest.raises(TypeError, match="wrong type"):
        ctap_wrong_type.send_cbor(0x04)


def test_info_identifier_and_assertion_helpers():
    pin_token = b"P" * 32
    secret = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"\x00" * 32,
        info=b"encIdentifier",
        backend=default_backend(),
    ).derive(pin_token)

    iv = b"I" * 16
    plaintext = b"0123456789abcdef"
    encryptor = Cipher(
        algorithms.AES(secret), modes.CBC(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    info = base_module.Info(versions=["FIDO_2_0"], enc_identifier=iv + ciphertext)
    assert info.get_identifier(pin_token) == plaintext

    info_without_identifier = base_module.Info(versions=["FIDO_2_0"])
    assert info_without_identifier.get_identifier(pin_token) is None

    public_key = mock.Mock()
    assertion_auth_data = AuthenticatorData.create(
        b"A" * 32,
        int(AuthenticatorData.FLAG.UP),
        1,
    )
    assertion = base_module.AssertionResponse(
        credential={"id": b"id", "type": "public-key"},
        auth_data=assertion_auth_data,
        signature=b"sig",
    )
    assertion.verify(b"client", public_key)
    public_key.verify.assert_called_once_with(assertion_auth_data + b"client", b"sig")

    auth = types.SimpleNamespace(
        user_presence=int(AuthenticatorData.FLAG.UP),
        counter=42,
        signature=b"ctap1-signature",
    )
    converted = base_module.AssertionResponse.from_ctap1(
        b"R" * 32,
        {"id": b"id", "type": "public-key"},
        auth,
    )
    assert converted.signature == b"ctap1-signature"
    assert converted.auth_data.counter == 42


def test_ctap2_wrapper_and_option_selection_branches(monkeypatch):
    sent = []

    def _send(cmd, data=None, *, event=None, on_keepalive=None):
        sent.append((cmd, data, event, on_keepalive))
        return {1: "ok"}

    ctap = _bare_ctap(lambda *_args: b"\x00", options={"credMgmt": True, "bioEnroll": True})
    monkeypatch.setattr(ctap, "send_cbor", _send, raising=False)

    assert ctap.info is ctap._info

    ctap.reset()
    ctap.client_pin(1, 2, permissions=3, permissions_rpid="example.com")
    ctap.credential_mgmt(9, {1: 2}, pin_uv_protocol=1, pin_uv_param=b"p")
    ctap.bio_enrollment(
        modality=1,
        sub_cmd=2,
        sub_cmd_params={3: 4},
        pin_uv_protocol=1,
        pin_uv_param=b"q",
        get_modality=True,
    )
    ctap.selection()
    ctap.large_blobs(
        offset=7,
        get=3,
        set=b"data",
        length=4,
        pin_uv_param=b"x",
        pin_uv_protocol=2,
    )
    ctap.config(sub_cmd=5, sub_cmd_params={7: 8}, pin_uv_protocol=1, pin_uv_param=b"y")

    assert sent[0][0] == base_module.Ctap2.CMD.RESET
    assert sent[1][0] == base_module.Ctap2.CMD.CLIENT_PIN
    assert sent[2][0] == base_module.Ctap2.CMD.CREDENTIAL_MGMT
    assert sent[3][0] == base_module.Ctap2.CMD.BIO_ENROLLMENT
    assert sent[4][0] == base_module.Ctap2.CMD.SELECTION
    assert sent[5][0] == base_module.Ctap2.CMD.LARGE_BLOBS
    assert sent[6][0] == base_module.Ctap2.CMD.CONFIG

    sent.clear()
    ctap._info.options = {"credentialMgmtPreview": True}
    ctap.credential_mgmt(1)
    assert sent[-1][0] == base_module.Ctap2.CMD.CREDENTIAL_MGMT_PRE

    sent.clear()
    ctap._info.options = {"userVerificationMgmtPreview": True}
    ctap.bio_enrollment()
    assert sent[-1][0] == base_module.Ctap2.CMD.BIO_ENROLLMENT_PRE

    ctap._info.options = {}
    with pytest.raises(ValueError, match="Credential Management not supported"):
        ctap.credential_mgmt(1)
    with pytest.raises(ValueError, match="does not support Bio Enroll"):
        ctap.bio_enrollment()


def test_get_next_assertion_and_get_assertions_paths(monkeypatch):
    ctap = _bare_ctap(lambda *_args: b"\x00")
    monkeypatch.setattr(ctap, "send_cbor", lambda *_args, **_kwargs: {1: "payload"}, raising=False)

    sentinel = object()
    monkeypatch.setattr(
        base_module.AssertionResponse,
        "from_dict",
        classmethod(lambda cls, value: sentinel),
        raising=False,
    )
    assert ctap.get_next_assertion() is sentinel

    first = types.SimpleNamespace(number_of_credentials=3)
    tail = [object(), object()]
    monkeypatch.setattr(ctap, "get_assertion", lambda *_args, **_kwargs: first, raising=False)
    monkeypatch.setattr(ctap, "get_next_assertion", lambda: tail.pop(0), raising=False)
    assertions = ctap.get_assertions("rp-id", b"hash")
    assert assertions[0] is first
    assert len(assertions) == 3

    first_single = types.SimpleNamespace(number_of_credentials=None)
    called = {"count": 0}

    def _unexpected_next():
        called["count"] += 1
        return object()

    monkeypatch.setattr(ctap, "get_assertion", lambda *_args, **_kwargs: first_single, raising=False)
    monkeypatch.setattr(ctap, "get_next_assertion", _unexpected_next, raising=False)
    assert ctap.get_assertions("rp-id", b"hash") == [first_single]
    assert called["count"] == 0


def test_ctap2_init_rejects_device_without_cbor_capability():
    device = types.SimpleNamespace(capabilities=0)
    with pytest.raises(ValueError, match="does not support CTAP2"):
        base_module.Ctap2(device)
