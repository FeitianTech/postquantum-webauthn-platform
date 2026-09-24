"""The codec names CTAP request parameters and response members as CTAP 2.2 does.

Both the decoder and the encoder used to call makeCredential key 0x0B and
getAssertion key 0x08 "largeBlobKey". In CTAP 2.2 makeCredential 0x0B is
attestationFormatsPreference, and getAssertion has no parameter 0x08; the
largeBlobKey members exist only in the two responses. The members both
responses number last are unsignedExtensionOutputs, not "extensions".
"""
from __future__ import annotations

import hashlib
import json

import pytest

from fido2 import cbor
from fido2.webauthn import AuthenticatorData
from server.app.decoder import decode_payload_text, encode_payload_text

_AUTH_DATA = bytes(AuthenticatorData.create(hashlib.sha256(b"example.com").digest(), 0x05, 7))


def _make_credential_request(**extra) -> bytes:
    body = {
        1: b"\x11" * 32,
        2: {"id": "example.com"},
        3: {"id": b"user-1", "name": "alice"},
        4: [{"alg": -7, "type": "public-key"}],
    }
    body.update({int(key[1:]): value for key, value in extra.items()})
    return b"\x01" + cbor.encode(body)


def _get_assertion_request(**extra) -> bytes:
    body = {1: "example.com", 2: b"\x22" * 32, 3: [{"type": "public-key", "id": b"\x01\x02"}]}
    body.update({int(key[1:]): value for key, value in extra.items()})
    return b"\x02" + cbor.encode(body)


def _decoded(raw: bytes) -> dict:
    return decode_payload_text(raw.hex())["data"]


def _encode(body, target: str = "cbor") -> dict:
    return encode_payload_text(json.dumps(body), target)


# -- decoding ---------------------------------------------------------------


def test_make_credential_key_0x0b_decodes_as_attestation_formats_preference():
    decoded = _decoded(_make_credential_request(k11=["packed", "none"]))

    for view in (decoded["ctapDecoded"]["makeCredentialRequest"], decoded["expandedJson"]):
        assert view["11 (attestationFormatsPreference)"] == ["packed", "none"]
        assert not any("largeBlobKey" in key for key in view)


def test_get_assertion_key_0x08_is_shown_unlabelled():
    decoded = _decoded(_get_assertion_request(k8=b"\x01\x02"))

    for view in (decoded["ctapDecoded"]["getAssertionRequest"], decoded["expandedJson"]):
        assert view["8"] == "0102"
        assert not any("largeBlobKey" in key for key in view)


def test_response_members_carry_their_ctap_2_2_names():
    make_credential = _decoded(b"\x00" + cbor.encode({1: "none", 2: _AUTH_DATA, 3: {}, 5: b"\x0b", 6: {"x": 1}}))
    for view in (make_credential["ctapDecoded"]["makeCredentialResponse"], make_credential["expandedJson"]):
        assert view["5 (largeBlobKey)"] == "0b"
        assert view["6 (unsignedExtensionOutputs)"] == {"x": 1}

    get_assertion = _decoded(
        b"\x00" + cbor.encode({1: {"type": "public-key", "id": b"\x01"}, 2: _AUTH_DATA, 3: b"\x30" * 8, 7: b"\x0b", 8: {"x": 1}})
    )
    for view in (get_assertion["ctapDecoded"]["getAssertionResponse"], get_assertion["expandedJson"]):
        assert view["7 (largeBlobKey)"] == "0b"
        assert view["8 (unsignedExtensionOutputs)"] == {"x": 1}


# -- encoding ---------------------------------------------------------------


def _get_assertion_structure(**extra) -> dict:
    return {"1 (rpId)": "example.com", "2 (clientDataHash)": "22" * 32, **extra}


def _make_credential_structure(**extra) -> dict:
    return {
        "1 (clientDataHash)": "11" * 32,
        "2 (rp)": {"id": "example.com"},
        "3 (user)": {"id": "0102", "name": "alice"},
        "4 (pubKeyCredParams)": [{"alg": -7, "type": "public-key"}],
        **extra,
    }


@pytest.mark.parametrize(
    "field",
    [{"8 (largeBlobKey)": "0102"}, {"largeBlobKey": "0102"}],
)
def test_the_encoder_refuses_a_get_assertion_large_blob_key(field):
    with pytest.raises(ValueError, match="getAssertion"):
        _encode({"ctapDecoded": {"getAssertionRequest": _get_assertion_structure(**field)}})
    with pytest.raises(ValueError, match="getAssertion"):
        _encode({"expandedJson": _get_assertion_structure(**field)})


def test_the_ctap_webauthn_encoder_refuses_a_get_assertion_large_blob_key():
    with pytest.raises(ValueError, match="0x08"):
        _encode({"01 (rpId)": "example.com", "02 (clientDataHash)": "22" * 32, "08 (largeBlobKey)": "0102"}, "CBOR (CTAP/WebAuthn Data)")


def test_the_ctap_webauthn_encoder_passes_an_unnamed_key_8_through_without_a_label():
    result = _encode({"01": "example.com", "02": "22" * 32, "08": "0102"}, "CBOR (CTAP/WebAuthn Data)")

    assert cbor.decode(bytes.fromhex(result["data"]["binary"]["hex"])[1:])[8] == b"\x01\x02"
    labels = result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert "8" in labels
    assert "largeBlobKey" not in labels


def test_the_encoder_refuses_a_make_credential_large_blob_key():
    with pytest.raises(ValueError, match="attestationFormatsPreference"):
        _encode({"ctapDecoded": {"makeCredentialRequest": _make_credential_structure(**{"11 (largeBlobKey)": "0102"})}})
    with pytest.raises(ValueError, match="makeCredential"):
        _encode({"ctapDecoded": {"makeCredentialRequest": _make_credential_structure(largeBlobKey="0102")}})
    with pytest.raises(ValueError, match="attestationFormatsPreference"):
        _encode(
            {
                "01": "11" * 32,
                "02": {"id": "example.com"},
                "03": {"id": "0102", "name": "alice"},
                "04": [{"alg": -7, "type": "public-key"}],
                "11 (largeBlobKey)": "0102",
            },
            "CBOR (CTAP/WebAuthn Data)",
        )


def test_the_encoder_emits_attestation_formats_preference_as_an_array_of_strings():
    structure = _make_credential_structure(**{"11 (attestationFormatsPreference)": ["packed", "none"]})
    result = _encode({"ctapDecoded": {"makeCredentialRequest": structure}})

    assert cbor.decode(bytes.fromhex(result["data"]["binary"]["hex"])[1:])[11] == ["packed", "none"]

    numeric = _encode(
        {
            "01": "11" * 32,
            "02": {"id": "example.com"},
            "03": {"id": "0102", "name": "alice"},
            "04": [{"alg": -7, "type": "public-key"}],
            "11": ["packed"],
        },
        "CBOR (CTAP/WebAuthn Data)",
    )
    assert numeric["data"]["ctapDecoded"]["makeCredentialRequest"]["attestationFormatsPreference"] == ["packed"]

    with pytest.raises(ValueError, match="attestationFormatsPreference"):
        _encode({"ctapDecoded": {"makeCredentialRequest": _make_credential_structure(attestationFormatsPreference="packed")}})


def test_the_encoder_writes_unsigned_extension_outputs_at_the_response_members_number():
    structure = {
        "1 (credential)": {"type": "public-key", "id": "01"},
        "2 (authData)": _AUTH_DATA.hex(),
        "3 (signature)": "30" * 8,
        "8 (unsignedExtensionOutputs)": {"x": 1},
    }
    result = _encode({"ctapDecoded": {"getAssertionResponse": structure}})

    assert cbor.decode(bytes.fromhex(result["data"]["binary"]["hex"])[1:])[8] == {"x": 1}


def test_request_fields_named_only_by_number_are_refused_not_dropped():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    mapping = encode_module._encode_get_assertion_request({1: "example.com", 2: "22" * 32})

    assert (mapping[1], mapping[2]) == ("example.com", b"\x22" * 32)
    # 0x0c is not a getAssertion parameter: it is neither encoded nor dropped.
    with pytest.raises(ValueError, match="getAssertionRequest has no member '0x0c'"):
        encode_module._encode_get_assertion_request({1: "example.com", 2: "22" * 32, "0x0c": "raw"})
    with pytest.raises(ValueError, match="no parameter named 0xzz"):
        encode_module._encode_get_assertion_request({1: "example.com", 2: "22" * 32, "0xzz": "raw"})
