import base64

import pytest

from server.app.routes.simple import parsing as simple_parsing
from server.app.webauthn import client_binary
from tests.app.security.ceremony_helpers import b64u
from tests.app.storage.credential_seed import sample_public_key_bytes


def _valid_credential_entry(**overrides):
    entry = {
        "email": "user@example.com",
        "userName": "user@example.com",
        "displayName": "User",
        "type": "simple",
        "aaguid": b64u(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "credentialId": b64u(b"simple-credential-1"),
        "publicKey": b64u(sample_public_key_bytes()),
        "signCount": 7,
        "algorithm": -7,
    }
    entry.update(overrides)
    return entry


def test_decode_binary_value_decodes_base64url_string():
    raw = b"\x00\x01\xfe\xff"

    assert client_binary.read(b64u(raw), iterables=True) == raw


def test_decode_binary_value_decodes_standard_base64_string():
    raw = b"\xfb\xef\xff"
    encoded = base64.b64encode(raw).decode("ascii")

    assert client_binary.read(encoded, iterables=True) == raw


def test_decode_binary_value_falls_back_to_hex_when_base64_decoders_fail():
    # Separated or spaced hex cannot be base64, so it reaches the hex reading.
    assert client_binary.read("41 42 43", iterables=True) == b"ABC"
    assert client_binary.read("41:42:43", iterables=True) == b"ABC"

    # An unbroken run of hex digits can be valid base64 as well, and base64
    # still wins where it is: the precedence predates the strictness work and
    # is left alone so stored credential IDs keep decoding to the same bytes.
    assert client_binary.read("0000", iterables=True) == base64.b64decode("0000")

    # "414243" is not canonical base64 -- its final quantum carries bits that
    # re-encode to something else -- so it is no longer accepted as base64 and
    # falls through to the hex reading it plainly is.
    assert client_binary.read("414243", iterables=True) == b"ABC"


def test_decode_binary_value_decodes_iterable_of_ints():
    assert client_binary.read([65, 66, 67], iterables=True) == b"ABC"


@pytest.mark.parametrize(
    "value,pattern",
    [
        (None, "missing binary value"),
        ("   ", "empty binary value"),
        ("g$", "invalid binary value"),
        (1234, "unsupported binary value type"),
        (["A"], "invalid iterable value"),
    ],
)
def test_decode_binary_value_rejects_invalid_inputs(value, pattern):
    with pytest.raises(ValueError, match=pattern):
        client_binary.read(value, iterables=True)


def test_parse_client_credentials_returns_empty_for_non_list_input():
    credentials, serialized = simple_parsing._parse_client_credentials({"not": "a-list"})

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_skips_entries_missing_required_fields():
    credentials, serialized = simple_parsing._parse_client_credentials(
        [
            {"credentialId": b64u(b"id-only"), "publicKey": b64u(sample_public_key_bytes())},
            {"aaguid": b64u(bytes(16)), "publicKey": b64u(sample_public_key_bytes())},
            {"aaguid": b64u(bytes(16)), "credentialId": b64u(b"id-only")},
        ]
    )

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_parses_aliases_and_serializes_metadata_fields():
    aaguid_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"alias-credential"
    public_key_bytes = sample_public_key_bytes()

    entry = {
        "email": "alias@example.com",
        "userName": "alias@example.com",
        "displayName": "Alias User",
        "type": "simple",
        "aaguidBase64": base64.b64encode(aaguid_bytes).decode("ascii"),
        "credentialID": b64u(credential_id),
        "publicKeyBase64Url": b64u(public_key_bytes),
        "signCount": 11,
        "publicKeyAlgorithm": -8,
    }

    credentials, serialized = simple_parsing._parse_client_credentials([entry])

    assert len(credentials) == 1
    assert len(serialized) == 1

    payload = serialized[0]
    assert payload["credentialId"] == b64u(credential_id)
    assert payload["aaguid"] == b64u(aaguid_bytes)
    assert payload["publicKey"] == b64u(public_key_bytes)
    assert payload["signCount"] == 11
    assert payload["algorithm"] == -8
    assert payload["publicKeyAlgorithm"] == -8
    assert payload["email"] == "alias@example.com"
    assert payload["userName"] == "alias@example.com"
    assert payload["displayName"] == "Alias User"
    assert payload["type"] == "simple"


def test_parse_client_credentials_skips_malformed_entries_and_keeps_valid_entries():
    malformed = _valid_credential_entry(credentialId="g$")
    valid = _valid_credential_entry(credentialId=b64u(b"good-credential"), signCount=4)

    credentials, serialized = simple_parsing._parse_client_credentials([malformed, valid])

    assert len(credentials) == 1
    assert len(serialized) == 1
    assert serialized[0]["credentialId"] == b64u(b"good-credential")
    assert serialized[0]["signCount"] == 4
