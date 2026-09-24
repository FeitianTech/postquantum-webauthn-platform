"""Extensions are interpreted wherever they occur, and an unknown one is kept.

CTAP 2.2 section 12 defines the authenticator extensions (inputs in
makeCredential 0x06 and getAssertion 0x04, outputs in authData under the ED
flag or in unsignedExtensionOutputs); WebAuthn L3 section 10.1 defines the
client extension results. No device capture in this repository carries
extensions, so the hmac-secret values are WebAuthn L3 section 16.17.1.2's
published test vectors and the rest is built here.
"""
from __future__ import annotations

import base64
import json

import cbor2
import pytest

from server.app.decoder import decode_payload_text
from tests.app.decoder.real_vectors import (
    WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT,
    WEBAUTHN_L3_PACKED_SELF_CLIENT_DATA_JSON,
)

# WebAuthn L3 section 16.17.1.2, "CTAP2 hmac-secret extension".
_KEY_AGREEMENT = {
    1: 2,
    3: -25,
    -1: 1,
    -2: bytes.fromhex("a30522c2de402b561965c3cf949a1cab020c6f6ea36fcf7e911ac1a0f1515300"),
    -3: bytes.fromhex("9961a929abdb2f42e6566771887d41484d889e735e3248518a53112d2b915f00"),
}
_SALT_ENC_ONE_PROTOCOL_2 = bytes.fromhex(
    "23dde5e3462daf36559b85c4ac5f9656aa9bfd81c1dc2bf8533c8b9f3882854786b4f500e25b4e3d81f7fc7c74236229"
)
_SALT_ENC_TWO_PROTOCOL_2 = bytes.fromhex(
    "d9f4236403e0fe843a8e4e5be764d120904c198ad6e77b089876a3391961f183"
    "b0008b4ca66b91cd72aa35b6151ff981f6e5649f3c040e6615ad7dd8ae96ef23b229a5c97c3f0dcd8605eee166ce163a"
)
_SALT_ENC_ONE_PROTOCOL_1 = bytes.fromhex("ab8c878bb05d04700f077ed91845ec9c503c925cb12b327ddbeb4243c397f913")
_OUTPUT_ENC_ONE_PROTOCOL_2 = bytes.fromhex(
    "3bfaa48f7952330d63e35ff8cd5bca48d2a12823828915749287256ab146272f9fb437bf65691243c3f504bd7ea6d5e6"
)
_OUTPUT_ENC_TWO_PROTOCOL_2 = bytes.fromhex(
    "90ee52f739043bc17b3488a74306d7801debb5b61f18662c648a25b5b5678ede482cdaff99a537a44f064fcb10ce6e04"
    "dfd27619dc96a0daff8507e499296b1eecf0981f7c8518b277a7a3018f5ec6fb"
)
_OUTPUT_ENC_ONE_PROTOCOL_1 = bytes.fromhex("15d4e4f3f04109b492b575c1b38c28585b6719cf8d61304215108d939f37ccfb")

_UP, _AT, _ED = 0x01, 0x40, 0x80
_ES256_KEY = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: bytes(32), -3: bytes(32)})


def _auth_data(flags: int, extensions: dict) -> bytes:
    attested = bytes(16) + (2).to_bytes(2, "big") + b"id" + _ES256_KEY if flags & _AT else b""
    return bytes(32) + bytes([flags | _ED]) + bytes(4) + attested + cbor2.dumps(extensions)


def _blocks(data: bytes) -> list[dict]:
    return decode_payload_text(data.hex())["data"]["extensionsDecoded"]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_make_credential_inputs_are_interpreted():
    extensions = {
        "credProtect": 3,
        "credBlob": b"blob",
        "largeBlobKey": True,
        "largeBlob": {"support": "preferred"},
        "minPinLength": True,
        "pinComplexityPolicy": True,
        "hmac-secret": True,
        "hmac-secret-mc": {1: _KEY_AGREEMENT, 2: _SALT_ENC_ONE_PROTOCOL_2, 3: bytes(32), 4: 2},
        "thirdPartyPayment": True,
        "vendorExt": b"\x01\x02",
    }
    request = b"\x01" + cbor2.dumps({1: bytes(32), 2: {"id": "example.com"}, 3: {"id": b"u"}, 4: [], 6: extensions})

    (block,) = _blocks(request)
    entries = block["entries"]

    assert (block["role"], block["path"], block["location"]) == (
        "makeCredential input",
        "${6}",
        "extensions (0x06)",
    )
    assert entries["credProtect"]["meaning"] == "userVerificationRequired (0x03)"
    assert entries["credProtect"]["spec"] == "CTAP 2.2 section 12.1"
    assert entries["credBlob"] == {
        "value": b"blob".hex(),
        "known": True,
        "spec": "CTAP 2.2 section 12.2",
        "length": 4,
        "meaning": "the blob to store with the credential",
    }
    assert entries["largeBlobKey"]["meaning"] == "asks for a largeBlobKey for the new credential"
    assert entries["largeBlob"]["meaning"] == "large blob support preferred"
    assert entries["minPinLength"]["meaning"] == "asks for the current minimum PIN length"
    assert entries["pinComplexityPolicy"]["spec"] == "CTAP 2.2 section 12.6"
    assert entries["hmac-secret"]["meaning"] == "asks for an hmac-secret for the new credential"
    members = entries["hmac-secret-mc"]["members"]
    assert members["1 (keyAgreement)"]["keyType"] == "EC2 (2)"
    assert members["1 (keyAgreement)"]["curve"] == "P-256 (1)"
    assert members["2 (saltEnc)"]["meaning"] == "one salt, encrypted (pinUvAuthProtocol 2, member 0x04)"
    assert entries["thirdPartyPayment"]["spec"] == "CTAP 2.2 section 12.9"
    # Unknown: kept as sent, and said to be unknown.
    assert entries["vendorExt"] == {
        "value": "0102",
        "known": False,
        "meaning": "not defined in CTAP 2.2 section 12 or WebAuthn L3 section 10; shown as sent",
    }


@pytest.mark.parametrize(
    ("salt_enc", "protocol", "meaning"),
    [
        (_SALT_ENC_ONE_PROTOCOL_2, 2, "one salt, encrypted (pinUvAuthProtocol 2, member 0x04)"),
        (_SALT_ENC_TWO_PROTOCOL_2, 2, "two salts, encrypted (pinUvAuthProtocol 2, member 0x04)"),
        (
            _SALT_ENC_ONE_PROTOCOL_1,
            None,
            "one salt, encrypted (pinUvAuthProtocol 1: member 0x04 is absent (CTAP 2.2 section 12.7))",
        ),
        (bytes(40), 2, "40 bytes is not a length pinUvAuthProtocol 2, member 0x04 produces for one or two 32-byte salts"),
    ],
)
def test_the_hmac_secret_get_assertion_input_counts_its_salts_by_protocol(salt_enc, protocol, meaning):
    hmac_input = {1: _KEY_AGREEMENT, 2: salt_enc, 3: bytes(16 if protocol is None else 32)}
    if protocol is not None:
        hmac_input[4] = protocol
    request = b"\x02" + cbor2.dumps({1: "example.com", 2: bytes(32), 4: {"hmac-secret": hmac_input}})

    (block,) = _blocks(request)
    members = block["entries"]["hmac-secret"]["members"]

    assert block["role"] == "getAssertion input"
    assert members["2 (saltEnc)"]["meaning"] == meaning
    assert members["3 (saltAuth)"]["length"] in (16, 32)


def test_get_assertion_inputs_are_interpreted():
    extensions = {"credBlob": True, "largeBlobKey": True, "largeBlob": {"read": True}, "thirdPartyPayment": True}
    request = b"\x02" + cbor2.dumps({1: "example.com", 2: bytes(32), 4: extensions})

    entries = _blocks(request)[0]["entries"]

    assert entries["credBlob"]["meaning"] == "asks for the credential's credBlob"
    assert entries["largeBlob"]["meaning"] == "read the credential's large blob"
    assert entries["thirdPartyPayment"]["meaning"] == "asks whether the credential is for third-party payment"


@pytest.mark.parametrize(
    ("output", "meaning"),
    [
        (_OUTPUT_ENC_ONE_PROTOCOL_2, "one output, encrypted with PIN/UV auth protocol 2, after a 16-byte IV; not decrypted here"),
        (_OUTPUT_ENC_TWO_PROTOCOL_2, "two outputs, encrypted with PIN/UV auth protocol 2, after a 16-byte IV; not decrypted here"),
        (_OUTPUT_ENC_ONE_PROTOCOL_1, "one output, encrypted with PIN/UV auth protocol 1; not decrypted here"),
    ],
)
def test_get_assertion_outputs_in_authdata_are_interpreted(output, meaning):
    auth_data = _auth_data(_UP, {"hmac-secret": output, "credBlob": b"blob", "thirdPartyPayment": False})
    response = b"\x00" + cbor2.dumps({2: auth_data, 3: b"\x30\x00", 8: {"largeBlob": {"blob": b"z", "originalSize": 9}}})

    authenticator, unsigned = _blocks(response)

    assert (authenticator["role"], authenticator["path"]) == ("getAssertion output", "${2}<extensions>")
    assert authenticator["entries"]["hmac-secret"]["meaning"] == meaning
    assert authenticator["entries"]["credBlob"]["meaning"] == "the credential's credBlob"
    assert authenticator["entries"]["thirdPartyPayment"]["meaning"] == (
        "the credential was not made for third-party payment"
    )
    assert (unsigned["role"], unsigned["path"]) == ("getAssertion unsigned output", "${8}")
    assert unsigned["entries"]["largeBlob"]["meaning"] == "the stored blob, 1 bytes compressed"


def test_make_credential_outputs_in_authdata_are_interpreted():
    auth_data = _auth_data(
        _UP | _AT,
        {
            "credProtect": 2,
            "credBlob": False,
            "minPinLength": 6,
            "pinComplexityPolicy": True,
            "hmac-secret": True,
            "largeBlobKey": bytes(32),
            "thirdPartyPayment": True,
        },
    )
    response = b"\x00" + cbor2.dumps({1: "none", 2: auth_data, 3: {}, 6: {"largeBlob": {"supported": True}}})

    authenticator, unsigned = _blocks(response)
    entries = authenticator["entries"]

    assert authenticator["role"] == "makeCredential output"
    assert entries["credProtect"]["meaning"] == "userVerificationOptionalWithCredentialIDList (0x02)"
    assert entries["credBlob"]["meaning"].startswith("the credBlob was not stored")
    assert entries["minPinLength"]["meaning"] == "the current minimum PIN length: 6 Unicode code points"
    assert entries["pinComplexityPolicy"]["meaning"] == "a PIN complexity policy is enforced"
    assert entries["hmac-secret"]["meaning"] == "the authenticator made the credential's hmac-secret keys"
    assert "returns the key as the response member largeBlobKey" in entries["largeBlobKey"]["note"]
    assert entries["thirdPartyPayment"]["note"] == (
        "CTAP 2.2 section 12.9 defines no makeCredential output for thirdPartyPayment"
    )
    assert unsigned["entries"]["largeBlob"]["meaning"] == "the new credential supports large blobs"


def test_an_attestation_object_reports_its_authdata_extensions():
    auth_data = _auth_data(_UP | _AT, {"credProtect": 1})
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    (block,) = _blocks(attestation)

    assert block["path"] == '${"authData"}<extensions>'
    assert block["entries"]["credProtect"]["meaning"] == "userVerificationOptional (0x01)"


@pytest.mark.parametrize(
    ("flags", "role", "basis"),
    [
        (_UP | _AT, "makeCredential output", "read as a registration's: the AT flag is set"),
        (_UP, "getAssertion output", "read as an assertion's: the AT flag is clear"),
    ],
)
def test_bare_authdata_says_how_it_read_the_ceremony(flags, role, basis):
    (block,) = _blocks(_auth_data(flags, {"credBlob": True}))

    assert (block["role"], block["basis"], block["path"]) == (role, basis, "$<extensions>")


def test_client_extension_results_are_interpreted():
    credential = {
        "id": "AQID",
        "rawId": "AQID",
        "type": "public-key",
        "response": {
            "attestationObject": _b64url(WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT),
            "clientDataJSON": _b64url(WEBAUTHN_L3_PACKED_SELF_CLIENT_DATA_JSON),
        },
        "clientExtensionResults": {
            "credProps": {"rk": True},
            "prf": {"enabled": True, "results": {"first": _b64url(bytes(32))}},
            "largeBlob": {"supported": False},
            "appidExclude": True,
            "credBlob": True,
            "hmacCreateSecret": True,
            "hmacGetSecret": {"output1": _b64url(bytes(32)), "output2": "!!"},
            "getCredBlob": _b64url(b"blob"),
            "appid": False,
            "mystery": {"a": 1},
        },
    }

    (block,) = decode_payload_text(json.dumps(credential))["data"]["extensionsDecoded"]
    entries = block["entries"]

    assert (block["role"], block["path"]) == ("client output", "clientExtensionResults")
    assert entries["credProps"] == {
        "value": {"rk": True},
        "known": True,
        "spec": "WebAuthn L3 section 10.1.3",
        "meaning": "rk true: a client-side discoverable credential",
    }
    assert entries["prf"]["meaning"] == "the credential supports PRF"
    assert entries["prf"]["results"] == {"first": {"length": 32}}
    assert entries["largeBlob"]["meaning"] == "large blobs not supported"
    assert entries["appidExclude"]["spec"] == "WebAuthn L3 section 10.1.2"
    assert entries["appid"]["meaning"] == "the RP ID was used"
    assert entries["credBlob"]["spec"] == "CTAP 2.2 section 12.2"
    assert entries["hmacCreateSecret"]["meaning"] == "the authenticator processed hmac-secret"
    assert entries["hmacGetSecret"]["outputs"] == {"output1": {"length": 32}, "output2": {"note": "not base64url"}}
    assert entries["getCredBlob"]["length"] == 4
    assert entries["mystery"]["known"] is False
    assert entries["mystery"]["value"] == {"a": 1}


def test_an_assertions_authdata_and_client_results_are_both_read():
    auth_data = _auth_data(_UP, {"hmac-secret": _OUTPUT_ENC_ONE_PROTOCOL_2})
    credential = {
        "id": "AQID",
        "type": "public-key",
        "response": {
            "authenticatorData": _b64url(auth_data),
            "clientDataJSON": _b64url(b'{"type":"webauthn.get","challenge":"AA","origin":"https://example.org"}'),
            "signature": _b64url(b"\x30\x00"),
        },
        "clientExtensionResults": {"appid": True, "largeBlob": {"blob": _b64url(b"abc")}},
    }

    authenticator, client = decode_payload_text(json.dumps(credential))["data"]["extensionsDecoded"]

    assert (authenticator["source"], authenticator["path"]) == ("response.authenticatorData", "$<extensions>")
    assert authenticator["role"] == "getAssertion output"
    assert client["entries"]["appid"]["meaning"].startswith("the FIDO AppID was used")
    assert client["entries"]["largeBlob"]["meaning"] == "the stored blob, 3 bytes"


@pytest.mark.parametrize(
    ("extensions", "name", "note"),
    [
        ({"credProtect": 7}, "credProtect", "expected a credProtect value 0x01, 0x02 or 0x03 here; shown as sent"),
        ({"hmac-secret": "yes"}, "hmac-secret", "expected true here; shown as sent"),
        ({"credBlob": 5}, "credBlob", "expected a byte string here; shown as sent"),
        ({"largeBlob": {"support": "required", "extra": 1}}, "largeBlob", "extra: not in the section's CDDL (support)"),
    ],
)
def test_values_of_the_wrong_shape_are_noted_and_kept(extensions, name, note):
    request = b"\x01" + cbor2.dumps({1: bytes(32), 2: {"id": "example.com"}, 3: {"id": b"u"}, 4: [], 6: extensions})

    entry = _blocks(request)[0]["entries"][name]

    assert entry["note"] == note
    assert entry["value"] == extensions[name]


def test_an_extensions_parameter_that_is_not_a_map_is_shown_as_sent():
    request = b"\x02" + cbor2.dumps({1: "example.com", 2: bytes(32), 4: ["credBlob"]})

    (block,) = _blocks(request)

    assert block["value"] == ["credBlob"]
    assert block["note"] == "extensions are a map from extension identifier to value; this is not a map"


def test_nothing_to_interpret_adds_nothing():
    request = b"\x02" + cbor2.dumps({1: "example.com", 2: bytes(32)})

    assert "extensionsDecoded" not in decode_payload_text(request.hex())["data"]
