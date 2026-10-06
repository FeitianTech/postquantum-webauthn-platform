"""Tests of ctap message view behavior."""

import base64

import cbor2

from server.app.decoder.decode import cbor_parser, ctap_message_view
from tests.app.decoder.ctap_auth_bytes import _auth_header
from tests.app.python_fido2_vectors import GSR2_DER as _GSR2_DER


def _auth_data_with_trailing_pairs(pairs: list[tuple[int, object]]) -> bytes:
    trailing = b"".join(cbor2.dumps(key) + cbor2.dumps(value) for key, value in pairs)
    return _auth_header() + trailing


def _view(message: str, value: dict) -> dict:
    """The decoder's view of ``value``, a ``message``, built from its parsed nodes."""


    return ctap_message_view.view(message, cbor_parser.decode_item(cbor2.dumps(value))[0])


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
