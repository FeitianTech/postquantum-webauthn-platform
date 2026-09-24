"""What is inside authenticator data is checked like the message around it.

Authenticator data (WebAuthn L3 section 6.1) is a byte string that holds a
37-byte header, the attested credential data its AT flag announces and the
extensions its ED flag announces. Bytes after those are reported as a finding
at their offset in the input; they are never decoded and never dropped.
"""
from __future__ import annotations

import cbor2

from server.app.decoder import decode_payload_text
from tests.fido2.ctap2.test_ctap2 import _GA_RESP, _MC_RESP

_UP, _AT, _ED = 0x01, 0x40, 0x80
_SIGNATURE = bytes.fromhex("3006020101020101")
_ES256_KEY = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: bytes(range(32)), -3: bytes(range(32, 64))})


def _auth_data(flags: int, *, credential_key: bytes = b"", extensions: bytes = b"", tail: bytes = b"") -> bytes:
    attested = b""
    if credential_key:
        attested = bytes(16) + (4).to_bytes(2, "big") + b"cred" + credential_key
    return bytes(32) + bytes([flags]) + (7).to_bytes(4, "big") + attested + extensions + tail


def _authdata_findings(result: dict) -> list[dict]:
    return [finding for finding in result["findings"] if finding["code"] == "authdata-trailing-bytes"]


def test_bytes_after_the_header_of_an_assertion_are_a_finding_at_their_offset():
    auth_data = _auth_data(_UP, tail=b"\xaa\xbb\xcc")
    data = bytes([0]) + cbor2.dumps({2: auth_data, 3: _SIGNATURE})

    result = decode_payload_text(data.hex())
    (finding,) = _authdata_findings(result)

    assert finding["offset"] == data.index(auth_data) + 37
    assert data[finding["offset"] :].startswith(b"\xaa\xbb\xcc")
    assert finding["path"] == "${2}"
    assert finding["hex"] == "aabbcc"
    assert finding["length"] == 3
    assert finding["category"] == "trailing"
    assert finding["message"] in result["malformed"]
    # Still shown where it was: the decoded view keeps the bytes.
    decoded = result["data"]["ctapDecoded"]["getAssertionResponse"]["2 (authData)"]
    assert decoded["trailingBytesHex"] == "aabbcc"


def test_bytes_after_the_credential_public_key_are_a_finding():
    auth_data = _auth_data(_UP | _AT, credential_key=_ES256_KEY, tail=b"\x00\x01")
    data = bytes([0]) + cbor2.dumps({1: "none", 2: auth_data, 3: {}})

    (finding,) = _authdata_findings(decode_payload_text(data.hex()))

    assert finding["offset"] == data.index(auth_data) + len(auth_data) - 2
    assert finding["hex"] == "0001"


def test_extensions_sent_without_the_ed_flag_are_bytes_after_the_header():
    extensions = cbor2.dumps({"credProtect": 2})
    auth_data = _auth_data(_UP, extensions=extensions)
    data = bytes([0]) + cbor2.dumps({2: auth_data, 3: _SIGNATURE})

    (finding,) = _authdata_findings(decode_payload_text(data.hex()))

    assert finding["hex"] == extensions.hex()


def test_extensions_announced_by_the_ed_flag_are_not_trailing():
    auth_data = _auth_data(_UP | _ED, extensions=cbor2.dumps({"credProtect": 2}))
    data = bytes([0]) + cbor2.dumps({2: auth_data, 3: _SIGNATURE})

    assert _authdata_findings(decode_payload_text(data.hex())) == []


def test_a_text_keyed_attestation_map_reports_its_authdata_path():
    # An attestation object whose authData has a tail is not a valid
    # attestation object; it is still read, as a makeCredential-shaped map.
    auth_data = _auth_data(_UP | _AT, credential_key=_ES256_KEY, tail=b"\xff")
    data = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    (finding,) = _authdata_findings(decode_payload_text(data.hex()))

    assert finding["path"] == '${"authData"}'
    assert finding["offset"] == data.index(auth_data) + len(auth_data) - 1


def test_real_device_responses_have_nothing_left_inside_authdata():
    for response in (_MC_RESP, _GA_RESP):
        result = decode_payload_text("00" + response.hex())
        assert _authdata_findings(result) == []
