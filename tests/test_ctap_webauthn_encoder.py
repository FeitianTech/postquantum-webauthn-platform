import json
import sys
from collections import OrderedDict
from pathlib import Path

import cbor2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from server.decoder.encode import encode_payload_text


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

    expected_bytes = bytes([0x00]) + cbor2.dumps(expected_map)
    assert encoded_hex == expected_bytes.hex()
