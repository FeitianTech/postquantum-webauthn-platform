import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sample_public_key_bytes() -> bytes:
    from fido2 import cbor

    return cbor.encode(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )


def _valid_credential_entry(**overrides):
    entry = {
        "email": "user@example.com",
        "userName": "user@example.com",
        "displayName": "User",
        "type": "simple",
        "aaguid": _b64url(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "credentialId": _b64url(b"simple-credential-1"),
        "publicKey": _b64url(_sample_public_key_bytes()),
        "signCount": 7,
        "algorithm": -7,
    }
    entry.update(overrides)
    return entry


def test_decode_binary_value_decodes_base64url_string():
    simple_module = pytest.importorskip("server.app.routes.simple")

    raw = b"\x00\x01\xfe\xff"

    assert simple_module._decode_binary_value(_b64url(raw)) == raw


def test_decode_binary_value_decodes_standard_base64_string():
    simple_module = pytest.importorskip("server.app.routes.simple")

    raw = b"\xfb\xef\xff"
    encoded = base64.b64encode(raw).decode("ascii")

    assert simple_module._decode_binary_value(encoded) == raw


def test_decode_binary_value_falls_back_to_hex_when_base64_decoders_fail(monkeypatch):
    simple_module = pytest.importorskip("server.app.routes.simple")

    def _raise_decode_error(*_args, **_kwargs):
        raise ValueError("decode failure")

    monkeypatch.setattr(simple_module.base64, "urlsafe_b64decode", _raise_decode_error)
    monkeypatch.setattr(simple_module.base64, "b64decode", _raise_decode_error)

    assert simple_module._decode_binary_value("414243") == b"ABC"


def test_decode_binary_value_decodes_iterable_of_ints():
    simple_module = pytest.importorskip("server.app.routes.simple")

    assert simple_module._decode_binary_value([65, 66, 67]) == b"ABC"


@pytest.mark.parametrize(
    "value,pattern",
    [
        (None, "missing binary value"),
        ("   ", "empty string"),
        ("g$", "invalid binary value"),
        (1234, "unsupported binary value type"),
        (["A"], "invalid iterable value"),
    ],
)
def test_decode_binary_value_rejects_invalid_inputs(value, pattern):
    simple_module = pytest.importorskip("server.app.routes.simple")

    with pytest.raises(ValueError, match=pattern):
        simple_module._decode_binary_value(value)


def test_parse_client_credentials_returns_empty_for_non_list_input():
    simple_module = pytest.importorskip("server.app.routes.simple")

    credentials, serialized = simple_module._parse_client_credentials({"not": "a-list"})

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_skips_entries_missing_required_fields():
    simple_module = pytest.importorskip("server.app.routes.simple")

    credentials, serialized = simple_module._parse_client_credentials(
        [
            {"credentialId": _b64url(b"id-only"), "publicKey": _b64url(_sample_public_key_bytes())},
            {"aaguid": _b64url(bytes(16)), "publicKey": _b64url(_sample_public_key_bytes())},
            {"aaguid": _b64url(bytes(16)), "credentialId": _b64url(b"id-only")},
        ]
    )

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_parses_aliases_and_serializes_metadata_fields():
    simple_module = pytest.importorskip("server.app.routes.simple")

    aaguid_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"alias-credential"
    public_key_bytes = _sample_public_key_bytes()

    entry = {
        "email": "alias@example.com",
        "userName": "alias@example.com",
        "displayName": "Alias User",
        "type": "simple",
        "aaguidBase64": base64.b64encode(aaguid_bytes).decode("ascii"),
        "credentialID": _b64url(credential_id),
        "publicKeyBase64Url": _b64url(public_key_bytes),
        "signCount": 11,
        "publicKeyAlgorithm": -8,
    }

    credentials, serialized = simple_module._parse_client_credentials([entry])

    assert len(credentials) == 1
    assert len(serialized) == 1

    payload = serialized[0]
    assert payload["credentialId"] == _b64url(credential_id)
    assert payload["aaguid"] == _b64url(aaguid_bytes)
    assert payload["publicKey"] == _b64url(public_key_bytes)
    assert payload["signCount"] == 11
    assert payload["algorithm"] == -8
    assert payload["publicKeyAlgorithm"] == -8
    assert payload["email"] == "alias@example.com"
    assert payload["userName"] == "alias@example.com"
    assert payload["displayName"] == "Alias User"
    assert payload["type"] == "simple"


def test_parse_client_credentials_skips_malformed_entries_and_keeps_valid_entries():
    simple_module = pytest.importorskip("server.app.routes.simple")

    malformed = _valid_credential_entry(credentialId="g$")
    valid = _valid_credential_entry(credentialId=_b64url(b"good-credential"), signCount=4)

    credentials, serialized = simple_module._parse_client_credentials([malformed, valid])

    assert len(credentials) == 1
    assert len(serialized) == 1
    assert serialized[0]["credentialId"] == _b64url(b"good-credential")
    assert serialized[0]["signCount"] == 4
