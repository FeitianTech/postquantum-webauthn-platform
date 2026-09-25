import base64

import cbor2
import pytest

from tests.fido2.attestation.test_attestation import _GSR2_DER


def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return bytes(range(32)) + bytes([flags]) + sign_count.to_bytes(4, "big")


def _auth_data_with_trailing_map(fields: dict) -> bytes:
    return _auth_header() + cbor2.dumps(fields)


def _auth_data_with_trailing_pairs(pairs: list[tuple[int, object]]) -> bytes:
    trailing = b"".join(cbor2.dumps(key) + cbor2.dumps(value) for key, value in pairs)
    return _auth_header() + trailing


def test_parse_authenticator_data_bytes_returns_parse_error_for_short_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(b"\x00" * 10)

    assert details["parseError"].startswith("Authenticator data shorter")
    assert trimmed == b"\x00" * 10
    assert trailing == b""


def test_parse_authenticator_data_bytes_parses_attested_and_extension_sections_with_trailing():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\xAA\xBB"
    public_key = cbor2.dumps({1: 2, 3: -7})
    extensions = cbor2.dumps({"credProtect": 1})
    trailer = b"\x00\xFF"

    payload = (
        _auth_header(flags=0xC1, sign_count=9)  # UP + AT + ED
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + public_key
        + extensions
        + trailer
    )

    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(payload)

    assert details["rpIdHash"] == bytes(range(32)).hex()
    assert details["flags"]["AT"] is True
    assert details["flags"]["ED"] is True
    assert details["attestedCredentialData"]["credentialId"] == "aabb"
    assert details["extensions"]["credProtect"] == 1
    # Only the bytes after the extensions trail; the extensions were read.
    assert trailing == trailer
    assert trimmed == payload[: len(payload) - len(trailer)]


def _view(message: str, value: dict) -> dict:
    """The decoder's view of ``value``, a ``message``, built from its parsed nodes."""

    from server.app.decoder.decode import cbor_parser, ctap_views

    return ctap_views.view(message, cbor_parser.decode_item(cbor2.dumps(value))[0])


def test_bytes_after_auth_data_are_reported_not_read_as_members_and_nothing_is_added():
    # Bytes after the end authData's flags describe are reported as they are.
    # They are not read as the response's signature, user or other members, and
    # no member the map did not hold is shown, not even as null.
    pairs = [(3, b"\xAA"), (4, {1: b"\x01", 2: "user@example.com", 3: "User"}), (5, 2)]
    auth_data = _auth_data_with_trailing_pairs(pairs)

    result = _view("getAssertionResponse", {2: auth_data})

    assert result["2 (authData)"]["trailingBytesHex"] == auth_data[37:].hex()
    assert set(result) == {"2 (authData)"}


def test_a_get_assertion_view_shows_only_what_the_map_held():
    auth_data = _auth_data_with_trailing_pairs(
        [
            (3, b"\x11\x22"),
            (4, {1: b"\x02", 2: b"alice", 3: b"Alice"}),
            (8, {"credBlob": b"\xFF"}),
            (10, b"\xCC"),
        ]
    )

    shown = _view("getAssertionResponse", {1: {2: "public-key", 1: b"\x10"}, 2: auth_data, 7: b"\x0A"})

    assert set(shown) == {"1 (credential)", "2 (authData)", "7 (largeBlobKey)"}
    assert shown["1 (credential)"] == {"2": "public-key", "1": "10"}
    assert shown["7 (largeBlobKey)"] == "0a"
    assert shown["2 (authData)"]["trailingBytesHex"] == auth_data[37:].hex()


def test_a_make_credential_view_shows_every_member_as_sent_and_each_certificate_with_its_bytes():
    auth_data = _auth_data_with_trailing_pairs([(7, b"\x99")])

    shown = _view(
        "makeCredentialResponse",
        {
            1: "packed",
            2: auth_data,
            3: {"alg": -7, "sig": b"\x01\x02", "x5c": [_GSR2_DER]},
            4: b"\x05",
            5: b"\x06",
            6: {"example": b"\x07"},
            99: b"\x08",
        },
    )

    assert shown["1 (fmt)"] == "packed"
    assert shown["3 (attStmt)"]["sig"] == "0102"
    assert shown["3 (attStmt)"]["alg"] == -7
    (certificate,) = shown["3 (attStmt)"]["x5c"]
    assert certificate["raw"] == _GSR2_DER.hex()
    assert "parsedX5c" in certificate
    assert shown["4 (epAtt)"] == "05"
    assert shown["5 (largeBlobKey)"] == "06"
    assert shown["6 (unsignedExtensionOutputs)"] == {"example": "07"}
    assert shown["99"] == "08"
    assert shown["2 (authData)"]["trailingBytesHex"] == auth_data[37:].hex()


def test_a_bare_map_of_a_make_credential_request_is_shown_as_one():
    from server.app.decoder import decode_payload_text

    value = {
        1: b"\x11" * 32,
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "name": "user", "displayName": "User"},
        4: [{"type": "public-key", "alg": -7}],
    }

    mapped = decode_payload_text(cbor2.dumps(value).hex())["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert mapped["1 (clientDataHash)"] == (b"\x11" * 32).hex()
    assert mapped["2 (rp)"]["id"] == "example.com"


def test_a_user_that_is_no_map_is_shown_as_it_was_sent():
    # A user entity sent as a byte string or as text is not re-read as CBOR,
    # base64 or hex to turn it into a map.
    encoded = cbor2.dumps({1: b"\xAA\xBB", 2: "alice"})
    request = {1: b"\x11" * 32, 2: {"id": "example.com"}, 4: [{"type": "public-key", "alg": -7}]}

    assert _view("makeCredentialRequest", {**request, 3: encoded})["3 (user)"] == encoded.hex()
    encoded_text = base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
    assert _view("makeCredentialRequest", {**request, 3: encoded_text})["3 (user)"] == encoded_text


def test_a_user_shows_each_member_with_its_type():
    request = {1: b"\x11" * 32, 2: {"id": "example.com"}, 4: [{"type": "public-key", "alg": -7}]}

    user = _view(
        "makeCredentialRequest",
        {**request, 3: {"id": b"\xAA\xBB", "name": b"alice", "displayName": "Alice", b"role": "admin"}},
    )["3 (user)"]

    # A name sent as bytes is shown as the bytes it is, never as text read from them.
    assert user == {"id": "aabb", "name": "616c696365", "displayName": "Alice", "h'726f6c65' (bytes)": "admin"}


def test_a_credential_descriptor_shows_every_member():
    descriptor = _view(
        "getAssertionRequest",
        {1: "example.com", 2: b"\x22" * 32, 3: [{"id": b"\x01\x02", "type": "public-key", "transports": ["usb", "nfc"], 9: b"\x03"}]},
    )["3 (allowList)"][0]

    assert descriptor == {"id": "0102", "type": "public-key", "transports": ["usb", "nfc"], "9": "03"}


def test_try_decode_cbor_interprets_prefixed_get_assertion_request_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    map_payload = cbor2.dumps({1: "example.com", 2: b"\x22" * 32})
    data = b"\x02" + map_payload

    result = decode_module._try_decode_cbor(data, "hex")

    assert result is not None
    assert result["format"] == "CBOR"
    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "command"
    assert list(decoded["ctapDecoded"]) == ["getAssertionRequest"]
    assert decoded["ctapDecoded"]["getAssertionRequest"]["1 (rpId)"] == "example.com"
    assert decoded["expandedJson"]["2 (clientDataHash)"] == (b"\x22" * 32).hex()
