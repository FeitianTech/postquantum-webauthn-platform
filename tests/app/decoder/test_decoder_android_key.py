"""The Android KeyDescription extension is read with cryptography's ASN.1 decoder.

The vector with a certificate is WebAuthn L3 section 16.14's android-key test
vector (the spec's test CA, not a device: no android-key capture exists in this
repository). The other KeyDescriptions are assembled below, in the test, to
reach the tags, versions and errors the vector does not.
"""
from __future__ import annotations

import hashlib

import cbor2

from server.app.decoder.decode import android_key
from tests.app.decoder.real_vectors import (
    PACKED_ATT_STMT,
    WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT,
    WEBAUTHN_L3_ANDROID_KEY_CLIENT_DATA_JSON,
)

# -- DER for the fixtures (test code only; the decoder reads DER with cryptography) --


def _tlv(identifier: bytes, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        length = bytes([size])
    elif size < 0x100:
        length = bytes([0x81, size])
    else:
        length = bytes([0x82]) + size.to_bytes(2, "big")
    return identifier + length + content


def _integer(value: int) -> bytes:
    return _tlv(b"\x02", value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def _octets(value: bytes) -> bytes:
    return _tlv(b"\x04", value)


def _sequence(*items: bytes) -> bytes:
    return _tlv(b"\x30", b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(b"\x31", b"".join(items))


def _enumerated(value: int) -> bytes:
    return _tlv(b"\x0a", bytes([value]))


def _explicit(number: int, inner: bytes) -> bytes:
    if number < 31:
        identifier = bytes([0xA0 | number])
    else:
        digits = []
        while number:
            digits.insert(0, number & 0x7F)
            number >>= 7
        identifier = bytes([0xBF] + [digit | 0x80 for digit in digits[:-1]] + [digits[-1]])
    return _tlv(identifier, inner)


_NULL = b"\x05\x00"


def _key_description(version: int, software: list[bytes], hardware: list[bytes], **overrides: bytes) -> bytes:
    parts = {
        "version": _integer(version),
        "attestation_level": _enumerated(1),
        "keymaster_version": _integer(4 if version < 100 else version),
        "keymaster_level": _enumerated(2),
        "challenge": _octets(b"\x11" * 32),
        "unique_id": _octets(b""),
    }
    parts.update(overrides)
    return _sequence(*parts.values(), _sequence(*software), _sequence(*hardware))


# -- the spec vector ------------------------------------------------------------


def test_the_webauthn_l3_vectors_key_description():
    attestation = cbor2.loads(WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT)

    view = android_key.read_certificate(attestation["attStmt"]["x5c"][0])

    assert view["attestationVersion"] == {"value": 300, "meaning": "KeyMint version 3.0"}
    assert view["attestationSecurityLevel"] == {"content": "00", "meaning": "Software"}
    assert view["keyMintVersion"] == {"value": 0}
    assert view["keyMintSecurityLevel"]["meaning"] == "Software"
    # Shown, not checked; here it is clientDataHash, as WebAuthn L3 section 8.4 wants.
    challenge = view["attestationChallenge"]
    assert challenge["hex"] == hashlib.sha256(WEBAUTHN_L3_ANDROID_KEY_CLIENT_DATA_JSON).hexdigest()
    assert "not checked" in challenge["note"]
    assert view["uniqueId"] == {"hex": "", "length": 0}
    assert view["softwareEnforced"] == {}
    assert view["hardwareEnforced"] == {
        "purpose": {"values": [2], "meanings": ["SIGN"]},
        "origin": {"value": 0, "meaning": "GENERATED"},
    }
    assert "errors" not in view


# -- the rest of the schema -----------------------------------------------------


def test_every_kind_of_authorization_list_entry():
    application_id = _sequence(
        _set(_sequence(_octets(b"com.example.app"), _integer(42))),
        _set(_octets(b"\xab" * 32)),
    )
    root_of_trust = _sequence(_octets(b"\x01" * 32), b"\x01\x01\xff", _enumerated(0), _octets(b"\x02" * 32))
    hardware = [
        _explicit(1, _set(_integer(2), _integer(3), _integer(9))),
        _explicit(2, _integer(3)),
        _explicit(3, _integer(256)),
        _explicit(5, _set(_integer(0), _integer(4))),
        _explicit(10, _integer(1)),
        _explicit(503, _NULL),
        _explicit(701, _integer(1_700_000_000_000)),
        _explicit(702, _integer(0)),
        _explicit(704, root_of_trust),
        _explicit(705, _integer(140000)),
        _explicit(706, _integer(202409)),
        _explicit(709, _octets(application_id)),
        _explicit(710, _octets(b"google")),
        _explicit(799, _integer(7)),  # a tag after this table
    ]

    view = android_key.read_key_description(_key_description(400, [], hardware))
    listed = view["hardwareEnforced"]

    assert "errors" not in view
    assert listed["purpose"] == {"values": [2, 3, 9], "meanings": ["SIGN", "VERIFY", "9 (not a value the schema names)"]}
    assert listed["algorithm"] == {"value": 3, "meaning": "EC"}
    assert listed["keySize"] == {"value": 256}
    assert listed["digest"] == {"values": [0, 4], "meanings": ["NONE", "SHA_2_256"]}
    assert listed["ecCurve"] == {"value": 1, "meaning": "P_256"}
    assert listed["noAuthRequired"] == {"present": True}
    assert listed["creationDateTime"]["utc"] == "2023-11-14T22:13:20+00:00"
    assert listed["origin"]["meaning"] == "GENERATED"
    assert listed["rootOfTrust"] == {
        "verifiedBootKey": "01" * 32,
        "deviceLocked": True,
        "verifiedBootState": {"content": "00", "meaning": "Verified"},
        "verifiedBootHash": "02" * 32,
    }
    assert listed["osVersion"]["version"] == "14.0.0"
    assert listed["osPatchLevel"] == {"value": 202409}
    assert listed["attestationApplicationId"]["packages"] == [{"name": "com.example.app", "version": 42}]
    assert listed["attestationApplicationId"]["signatureDigests"] == ["ab" * 32]
    assert listed["attestationIdBrand"]["text"] == "google"
    # Kept, with its identifier and content octets, never dropped.
    assert listed["unknown"] == [
        {"identifier": "bf861f", "content": "020107", "note": "a tag this table does not name; shown as sent"}
    ]
    assert view["attestationSecurityLevel"]["meaning"] == "TrustedEnvironment"
    assert view["keyMintSecurityLevel"]["meaning"] == "StrongBox"


def test_a_keymaster_description_uses_the_older_names_and_can_carry_all_applications():
    root_of_trust = _sequence(_octets(b"\x01" * 32), b"\x01\x01\x00", _enumerated(2))
    view = android_key.read_key_description(
        _key_description(2, [_explicit(600, _NULL)], [_explicit(704, root_of_trust)])
    )

    assert view["attestationVersion"]["meaning"] == "Keymaster version 3.0"
    assert view["keymasterVersion"] == {"value": 4, "meaning": "Keymaster version 4.0"}
    assert view["softwareEnforced"]["allApplications"] == {"present": True}
    assert view["teeEnforced"]["rootOfTrust"] == {
        "verifiedBootKey": "01" * 32,
        "deviceLocked": False,
        "verifiedBootState": {"content": "02", "meaning": "Unverified"},
    }


def test_an_error_names_its_field_and_the_rest_is_still_read():
    hardware = [_explicit(1, _set(_octets(b"x"))), _explicit(2, _integer(1))]

    view = android_key.read_key_description(_key_description(100, [], hardware))

    (error,) = view["errors"]
    assert error["field"] == "hardwareEnforced.purpose"
    assert view["hardwareEnforced"]["purpose"] is None
    assert view["hardwareEnforced"]["algorithm"] == {"value": 1, "meaning": "RSA"}


def test_a_field_of_the_wrong_type_is_located():
    view = android_key.read_key_description(_key_description(100, [], [], challenge=_integer(5)))

    assert [error["field"] for error in view["errors"]] == ["attestationChallenge"]
    assert "attestationChallenge" not in view


def test_security_levels_are_matched_on_their_content_octets():
    view = android_key.read_key_description(
        _key_description(100, [], [], attestation_level=_enumerated(9), keymaster_level=_integer(1))
    )

    assert view["attestationSecurityLevel"] == {"content": "09", "note": "not a value the schema names"}
    assert view["keyMintSecurityLevel"] == {"content": "01", "note": "not an ENUMERATED (identifier 02)"}


def test_what_is_not_a_key_description_is_said_so():
    assert android_key.read_key_description(_integer(1))["errors"][0]["field"] == "KeyDescription"
    assert android_key.read_certificate(b"not a certificate")["error"].startswith(
        "the credential certificate is not DER X.509"
    )
    # A packed attestation certificate carries no KeyDescription.
    assert android_key.read_certificate(PACKED_ATT_STMT["x5c"][0]) == {
        "note": "the credential certificate has no 1.3.6.1.4.1.11129.2.1.17 extension"
    }
