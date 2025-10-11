import json
import sys
from collections import OrderedDict
from pathlib import Path

import cbor2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from server.decoder.encode import encode_payload_text


def _canonical_key_order(keys):
    ordered = []
    for key in keys:
        encoded = cbor2.dumps(key, canonical=True)
        ordered.append((len(encoded), encoded, key))
    ordered.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ordered]


def test_ctap_webauthn_encoder_extracts_nested_numeric_payload():
    credential_id = "622518ecb4dd41109f3a62008c269c085f63"
    auth_data = "00" * 37
    signature = "11" * 64
    user_id = "25919e6571314d93977a51fb50597c64"

    nested_input = {
        "outer": {
            "decoded json": {
                "1 (credential)": {
                    "type": "public-key",
                    "id": credential_id,
                },
                "2 (authData)": {
                    "raw": auth_data,
                    "flags": {
                        "UP": True,
                        "UV": False,
                        "value": 0,
                    },
                },
                "3 (signature)": {
                    "hex": signature,
                },
                "4 (user)": {
                    "id": {"hex": user_id},
                    "name": "Example",  # descriptive value that should be preserved
                    "custom": "auxiliary",  # extra data should survive normalization
                },
                "5 (numberOfCredentials)": 1,
            }
        }
    }

    response = encode_payload_text(
        json.dumps(nested_input),
        "CBOR (CTAP/WebAuthn Data)",
    )

    assert response["success"] is True
    assert response["type"] == "CBOR (CTAP/WebAuthn Data) (encoded getAssertionResponse)"

    payload = response["data"]
    encoded_hex = payload["binary"]["hex"]

    expected_map = OrderedDict(
        [
            (
                1,
                OrderedDict(
                    [
                        ("type", "public-key"),
                        ("id", bytes.fromhex(credential_id)),
                    ]
                ),
            ),
            (2, bytes.fromhex(auth_data)),
            (3, bytes.fromhex(signature)),
            (
                4,
                OrderedDict(
                    [
                        ("id", bytes.fromhex(user_id)),
                        ("name", "Example"),
                        ("custom", "auxiliary"),
                    ]
                ),
            ),
            (5, 1),
        ]
    )

    expected_bytes = bytes([0x00]) + cbor2.dumps(expected_map, canonical=True)
    assert encoded_hex == expected_bytes.hex()


def test_ctap_webauthn_encoder_canonicalizes_display_order():
    credential_id = "622518ecb4dd41109f3a62008c269c085f63"
    auth_data = "00" * 37
    signature = "11" * 64
    user_id = "25919e6571314d93977a51fb50597c64"

    nested_input = {
        "outer": {
            "decoded json": {
                "1 (credential)": {
                    "type": "public-key",
                    "id": credential_id,
                    "transports": ["usb", "internal"],
                    "extra": {"b": 2, "a": 1},
                },
                "2 (authData)": {
                    "raw": auth_data,
                    "flags": {"UP": True, "UV": False, "value": 0},
                },
                "3 (signature)": {"hex": signature},
                "4 (user)": {
                    "id": {"hex": user_id},
                    "name": "Example",
                    "custom": "auxiliary",
                    "extras": {"2": "06", "10": "07"},
                },
                "5 (numberOfCredentials)": 1,
            }
        }
    }

    response = encode_payload_text(
        json.dumps(nested_input),
        "CBOR (CTAP/WebAuthn Data)",
    )

    payload = response["data"]
    encoded_value = payload["encodedValue"]
    credential_map = encoded_value["1"]
    assert list(credential_map.keys()) == _canonical_key_order(credential_map.keys())
    assert list(credential_map["extra"].keys()) == _canonical_key_order(
        credential_map["extra"].keys()
    )

    ctap_decoded = payload["ctapDecoded"]["getAssertionResponse"]
    assert list(ctap_decoded.keys()) == _canonical_key_order(ctap_decoded.keys())
    credential_decoded = ctap_decoded["credential"]
    assert list(credential_decoded.keys()) == _canonical_key_order(
        credential_decoded.keys()
    )
    user_extras = ctap_decoded["user"]["extras"]
    assert list(user_extras.keys()) == _canonical_key_order(user_extras.keys())


def test_ctap_webauthn_encoder_handles_wrapped_make_credential_request():
    client_data_hash = "11" * 32
    user_id = "aa" * 16

    wrapped_input = {
        "meta": {"source": "decoded json"},
        "payload": {
            "nested": {
                "decoded json": {
                    "1 (clientDataHash)": {"hex": client_data_hash},
                    "2 (rp)": {"id": "example.com", "name": "Example"},
                    "3 (user)": {
                        "id": {"hex": user_id},
                        "name": "User",  # preserved value
                        "displayName": "User Display",
                    },
                    "4 (pubKeyCredParams)": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257},
                    ],
                    "5 (excludeList)": [
                        {
                            "type": "public-key",
                            "id": {"hex": "22" * 16},
                        }
                    ],
                }
            }
        },
    }

    response = encode_payload_text(
        json.dumps(wrapped_input),
        "CBOR (CTAP/WebAuthn Data)",
    )

    assert response["success"] is True
    assert response["type"] == "CBOR (CTAP/WebAuthn Data) (encoded makeCredentialRequest)"

    encoded_hex = response["data"]["binary"]["hex"]
    encoded_bytes = bytes.fromhex(encoded_hex)

    assert encoded_bytes[0] == 0x01

    decoded_map = cbor2.loads(encoded_bytes[1:])
    assert decoded_map[1] == bytes.fromhex(client_data_hash)
    assert decoded_map[2] == {"id": "example.com", "name": "Example"}
    assert decoded_map[3] == {
        "id": bytes.fromhex(user_id),
        "name": "User",
        "displayName": "User Display",
    }
    assert decoded_map[4] == [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257},
    ]
    assert decoded_map[5] == [
        {
            "type": "public-key",
            "id": bytes.fromhex("22" * 16),
        }
    ]
