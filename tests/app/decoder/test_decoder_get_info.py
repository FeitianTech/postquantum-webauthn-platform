"""authenticatorGetInfo responses are read member by member: CTAP 2.2 section 6.4.

Built on the real getInfo response in tests/fido2/ctap2/test_ctap2.py (a
FIDO_2_0 security key), with and without its status byte, and on a map that
carries every member CTAP 2.2 defines, since no device captured here returns
the 2.1 and 2.2 members.
"""
from __future__ import annotations

import json

import cbor2
import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from server.app.webauthn import pqc
from tests.app.decoder.real_vectors import GET_INFO, GET_INFO_EXTRA_KEY

_AAGUID = bytes.fromhex("f8a011f38c0a4d15800617111f9edc7d")

_EVERY_MEMBER = {
    0x01: ["FIDO_2_0", "FIDO_2_1", "FIDO_2_2"],
    0x02: ["credProtect", "hmac-secret", "credBlob"],
    0x03: _AAGUID,
    0x04: {"rk": True, "up": True, "uv": False, "clientPin": True, "alwaysUv": False, "vendorThing": True},
    0x05: 2048,
    0x06: [2, 1],
    0x07: 8,
    0x08: 128,
    0x09: ["usb", "nfc"],
    0x0A: [{"alg": -50, "type": "public-key"}, {"alg": -49, "type": "public-key"}, {"alg": -7, "type": "public-key"}],
    0x0B: 1024,
    0x0C: False,
    0x0D: 6,
    0x0E: 0x050400,
    0x0F: 32,
    0x10: 2,
    0x11: 3,
    0x12: 0x00000202 | 0x00200000,
    0x13: {"FIDO": 4, "FIPS-CMVP-2": 2, "Vendor-Cert": 1},
    0x14: 25,
    0x15: [7],
    0x16: ["packed", "tpm"],
    0x17: 2,
    0x18: True,
    0x19: bytes(range(32)),
    0x1A: ["usb"],
    0x1B: True,
    0x1C: b"https://example.com/pin-policy",
    0x1D: 63,
}


def _get_info(data: bytes) -> dict:
    return decode_payload_text(data.hex())["data"]["ctapDecoded"]["getInfoResponse"]


def test_a_real_get_info_response_after_its_status_byte():
    result = decode_payload_text("00" + GET_INFO.hex())
    info = result["data"]["ctapDecoded"]["getInfoResponse"]

    assert result["type"] == "CBOR (SUCCESS status; GetInfo response)"
    assert result["findings"] == []
    assert "decodedValue" not in result["data"]
    assert info["1 (versions)"] == ["U2F_V2", "FIDO_2_0"]
    assert info["2 (extensions)"] == ["uvm", "hmac-secret"]
    assert info["3 (aaguid)"] == {"hex": _AAGUID.hex(), "guid": "f8a011f3-8c0a-4d15-8006-17111f9edc7d"}
    assert info["5 (maxMsgSize)"] == 1200
    assert info["6 (pinUvAuthProtocols)"] == [1]
    options = info["4 (options)"]
    assert options["rk"] == {
        "value": True,
        "meaning": "can create discoverable credentials, so it can answer getAssertion without an allowList",
        "defaultWhenAbsent": "false",
    }
    assert options["clientPin"]["meaning"] == "accepts a PIN from the client, but no PIN has been set yet"
    assert options["plat"]["meaning"] == "not a platform device"
    # Options not sent are named with what their absence means.
    assert options["uv"] == {
        "value": None,
        "sent": False,
        "meaning": "not sent; absent means: not supported: no built-in user verification method",
    }


def test_a_bare_get_info_map_is_read_the_same_way():
    result = decode_payload_text(GET_INFO.hex())

    assert result["type"] == "CBOR (GetInfo response)"
    assert result["data"]["ctapDecoded"]["getInfoResponse"] == _get_info(b"\x00" + GET_INFO)


def test_a_member_ctap_does_not_define_is_shown_and_labelled():
    info = _get_info(b"\x00" + GET_INFO_EXTRA_KEY)

    assert info["99 (not defined in CTAP 2.2)"] == 1234


def test_every_ctap_2_2_member_is_labelled():
    info = _get_info(b"\x00" + cbor2.dumps(_EVERY_MEMBER))

    assert list(info) == [
        "1 (versions)",
        "2 (extensions)",
        "3 (aaguid)",
        "4 (options)",
        "5 (maxMsgSize)",
        "6 (pinUvAuthProtocols)",
        "7 (maxCredentialCountInList)",
        "8 (maxCredentialIdLength)",
        "9 (transports)",
        "10 (algorithms)",
        "11 (maxSerializedLargeBlobArray)",
        "12 (forcePINChange)",
        "13 (minPINLength)",
        "14 (firmwareVersion)",
        "15 (maxCredBlobLength)",
        "16 (maxRPIDsForSetMinPINLength)",
        "17 (preferredPlatformUvAttempts)",
        "18 (uvModality)",
        "19 (certifications)",
        "20 (remainingDiscoverableCredentials)",
        "21 (vendorPrototypeConfigCommands)",
        "22 (attestationFormats)",
        "23 (uvCountSinceLastPinEntry)",
        "24 (longTouchForReset)",
        "25 (encIdentifier)",
        "26 (transportsForReset)",
        "27 (pinComplexityPolicy)",
        "28 (pinComplexityPolicyURL)",
        "29 (maxPINLength)",
    ]
    assert info["22 (attestationFormats)"] == ["packed", "tpm"]
    assert info["29 (maxPINLength)"] == 63


def test_algorithms_are_named_by_describe_algorithm_so_ml_dsa_is_named():
    algorithms = _get_info(cbor2.dumps(_EVERY_MEMBER))["10 (algorithms)"]

    assert [entry["algorithm"] for entry in algorithms] == [
        pqc.describe_algorithm(-50),
        pqc.describe_algorithm(-49),
        pqc.describe_algorithm(-7),
    ]
    assert algorithms[0] == {"alg": -50, "type": "public-key", "algorithm": "ML-DSA-87 (PQC)"}


def test_options_are_explained_and_unknown_ones_kept():
    options = _get_info(cbor2.dumps(_EVERY_MEMBER))["4 (options)"]

    assert options["uv"]["meaning"] == "has a built-in user verification method, but it is not configured yet"
    assert options["clientPin"]["meaning"] == "accepts a PIN from the client, and a PIN has been set"
    assert options["alwaysUv"]["meaning"] == "supports Always Require User Verification, but it is disabled"
    assert options["vendorThing"] == {
        "value": True,
        "known": False,
        "meaning": "not an option ID CTAP 2.2 section 6.4 defines",
    }
    assert options["makeCredUvNotRqd"]["sent"] is False


def test_uv_modality_certifications_and_byte_members_are_explained():
    info = _get_info(cbor2.dumps(_EVERY_MEMBER))

    assert info["18 (uvModality)"] == {
        "value": 0x00200202,
        "hex": "0x00200202",
        "methods": ["fingerprint_internal", "none"],
        "unknownBits": "0x00200000",
    }
    certifications = info["19 (certifications)"]
    assert certifications["FIDO"]["level"] == "L2+"
    assert certifications["FIPS-CMVP-2"]["value"] == 2
    assert certifications["Vendor-Cert"]["known"] is False
    assert info["28 (pinComplexityPolicyURL)"] == {
        "hex": b"https://example.com/pin-policy".hex(),
        "text": "https://example.com/pin-policy",
    }
    assert info["25 (encIdentifier)"]["length"] == 32
    assert "not decrypted here" in info["25 (encIdentifier)"]["meaning"]


def test_values_of_the_wrong_shape_are_shown_as_sent_with_a_note():
    info = _get_info(
        cbor2.dumps({1: ["FIDO_2_0"], 3: b"\x01\x02", 4: {"rk": "yes"}, 10: "ES256", 18: "x", 19: [1], 28: b"\xff"})
    )

    assert info["3 (aaguid)"]["note"] == "an aaguid is 16 bytes (CTAP 2.2 section 6.4); this one is 2"
    assert info["4 (options)"]["rk"]["meaning"] == "not a boolean: CTAP 2.2 option values are booleans"
    assert info["10 (algorithms)"] == "ES256"
    assert info["18 (uvModality)"] == "x"
    assert info["19 (certifications)"] == [1]
    assert info["28 (pinComplexityPolicyURL)"] == {"hex": "ff", "note": "not UTF-8 text"}


def test_a_key_that_is_not_an_integer_is_kept_and_labelled():
    info = _get_info(cbor2.dumps({1: ["FIDO_2_0"], 3: _AAGUID, "extra": b"\x01"}))

    assert info["extra (not a member: CTAP 2.2 numbers members with integer keys)"] == "01"


@pytest.mark.parametrize(
    "message",
    [
        {"1": ["FIDO_2_0"], "3": _AAGUID},  # text keys are not members
        {1: [], 3: _AAGUID},  # versions is required and not empty
        {1: ["FIDO_2_0"]},  # aaguid is required
    ],
)
def test_maps_without_the_required_members_are_not_read_as_get_info(message):
    result = decode_payload_text("00" + cbor2.dumps(message).hex())

    assert "GetInfo" not in result["type"]


def test_a_map_after_the_get_info_command_byte_is_not_labelled():
    # authenticatorGetInfo takes no parameters; what follows 0x04 is not its response.
    result = decode_payload_text("04" + GET_INFO.hex())

    assert result["type"] == "CBOR (GET_INFO command)"
    assert "ctapDecoded" not in result["data"]


def test_the_codec_route_returns_the_get_info_view(client):
    response = client.post("/api/codec", json={"payload": "00" + GET_INFO.hex(), "mode": "decode"})

    assert response.status_code == 200
    assert response.get_json()["data"]["ctapDecoded"]["getInfoResponse"]["5 (maxMsgSize)"] == 1200


def test_the_encoder_refuses_a_decoded_get_info_rather_than_encode_the_wrapper():
    decoded = decode_payload_text("00" + GET_INFO.hex())["data"]

    with pytest.raises(ValueError, match="getInfoResponse is not a CTAP message the encoder builds"):
        encode_payload_text(json.dumps(decoded), "cbor")
