"""Every CBOR item the repository's tests and golden records hold, for the codec's round-trip tests.

Each entry is one whole, strictly well-formed item, named by where it came
from. Sources: the real device and specification vectors
(``tests/app/decoder/real_vectors.py``); the attestation objects the
characterization goldens are built from; registration responses built as the
golden scenarios build them; python-fido2's own test CBOR vectors and CTAP
responses (one of them not canonical); every hex literal under ``tests/`` that
holds an item, with a leading CTAP command or status byte dropped where there
is one; every array, map or tag the characterization golden records and inputs
hold, in hex or base64url; and the COSE keys and extensions inside every
authenticator data above.
"""
from __future__ import annotations

import ast
import base64
import binascii
import functools
import json
import re
from pathlib import Path

from server.app.decoder.ctap_tables import COMMANDS, STATUSES
from server.app.decoder.decode.cbor_parser import _CborDecodingError, decode_item
from tests.app.characterization import material
from tests.app.decoder import real_vectors
from tests.app.python_fido2_vectors import CBOR_TEST_VECTORS as _TEST_VECTORS
from tests.app.python_fido2_vectors import CLIENT_MC_RESP as _CLIENT_MC_RESP

_TESTS = Path(__file__).resolve().parents[1]


def _whole_item(data: bytes) -> bytes | None:
    """``data`` when it is exactly one strictly well-formed item."""

    try:
        _node, end, _skipped = decode_item(data)
    except (_CborDecodingError, RecursionError):
        return None
    return data if end == len(data) else None


def _first_item(data: bytes) -> bytes | None:
    try:
        _node, end, _skipped = decode_item(data)
    except (_CborDecodingError, RecursionError):
        return None
    return data[:end]


def _auth_data_items(auth_data: bytes) -> dict[str, bytes]:
    """The credential public key and the extensions an authenticator data holds, as items."""

    found: dict[str, bytes] = {}
    if len(auth_data) < 37:
        return found
    flags, offset = auth_data[32], 37
    try:
        if flags & 0x40:
            id_length = int.from_bytes(auth_data[offset + 16 : offset + 18], "big")
            offset += 18 + id_length
            _node, end, _ = decode_item(auth_data, offset)
            found["credentialPublicKey"], offset = auth_data[offset:end], end
        if flags & 0x80:
            _node, end, _ = decode_item(auth_data, offset)
            found["extensions"] = auth_data[offset:end]
    except _CborDecodingError:
        pass
    return found


def _registration_objects() -> dict[str, bytes]:
    objects = {}
    for key_type in ("es256", "ed25519", "rs256", "ML-DSA-44", "ML-DSA-65"):
        payload = material.registration_payload(material.Authenticator(f"corpus-{key_type}", key_type=key_type),
                                                challenge=b"\x01" * 32)
        objects[f"registration:{key_type}:none"] = payload["response"]["attestationObject"]
    for attestation in ("self", "x5c"):
        payload = material.registration_payload(material.Authenticator(f"corpus-{attestation}"),
                                                challenge=b"\x02" * 32, attestation=attestation)
        objects[f"registration:es256:{attestation}"] = payload["response"]["attestationObject"]
    return {name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) for name, value in objects.items()}


def _hex_literals() -> dict[str, bytes]:
    """Every hex string literal under tests/ that holds an item, cut to the item."""

    found: dict[str, bytes] = {}
    for path in sorted(_TESTS.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            text = node.value.replace(" ", "")
            if len(text) < 4 or len(text) % 2 or not all(c in "0123456789abcdefABCDEF" for c in text):
                continue
            data = bytes.fromhex(text)
            candidates = [data]
            if data[0] in COMMANDS or data[0] in STATUSES:
                candidates.append(data[1:])
            for candidate in candidates:
                item = _first_item(candidate) if candidate else None
                if item and len(item) > 1:
                    found.setdefault(item.hex(), item)
    return {f"literal:{key[:24]}": item for key, item in found.items()}


_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")


def _golden_items() -> dict[str, bytes]:
    """Every array, map and tag longer than 8 bytes that a characterization record holds as text.

    A string is tried as hex, then as base64url or base64, with a leading CTAP
    command or status byte dropped where there is one. Scalars are left out: any
    short string reads as some scalar. Each item is named by the first record
    and JSON path it was found at.
    """

    found: dict[bytes, str] = {}

    def visit(value, where: str) -> None:
        if isinstance(value, dict):
            for key, entry in value.items():
                visit(entry, f"{where}.{key}")
        elif isinstance(value, list):
            for index, entry in enumerate(value):
                visit(entry, f"{where}[{index}]")
        elif isinstance(value, str) and len(value) > 8:
            for data in _binary_readings(value):
                for candidate in (data, data[1:]) if data[0] in COMMANDS or data[0] in STATUSES else (data,):
                    if len(candidate) > 8 and candidate[0] >> 5 in (4, 5, 6) and _whole_item(candidate):
                        found.setdefault(candidate, where)

    for path in sorted((_TESTS / "app" / "characterization").rglob("*.json")):
        visit(json.loads(path.read_text(encoding="utf-8")), path.stem)
    return {f"golden:{where}": item for item, where in found.items()}


def _binary_readings(text: str) -> list[bytes]:
    readings = []
    if _HEX.fullmatch(text):
        readings.append(bytes.fromhex(text))
    if _BASE64.fullmatch(text):
        try:
            readings.append(base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4)))
        except (binascii.Error, ValueError):
            pass
    return [data for data in readings if data]


@functools.cache
def corpus() -> dict[str, bytes]:
    """Name -> item, for every source above."""


    items: dict[str, bytes] = {}
    for name, value in sorted(vars(real_vectors).items()):
        if name.isupper() and isinstance(value, bytes) and _whole_item(value):
            items[f"real_vectors:{name}"] = value
    for name, value in material.captured_attestation_objects().items():
        items[f"captured-attestation-object:{name}"] = value
    items.update(_registration_objects())
    for hex_text, _value in _TEST_VECTORS:
        items[f"fido2-cbor-vector:{hex_text}"] = bytes.fromhex(hex_text)
    items["fido2-client:_MC_RESP (not canonical)"] = _CLIENT_MC_RESP
    items.update(_hex_literals())
    items.update(_golden_items())

    auth_data_sources = {name: value for name, value in vars(real_vectors).items() if name.endswith("_AUTH_DATA")}
    for name, value in list(items.items()):
        node, _end, _ = decode_item(value)
        for entry in node.get("entries") or []:
            if entry["key"].get("value") in ("authData", 2) and entry["value"].get("majorType") == 2:
                auth_data_sources[name] = bytes.fromhex(entry["value"]["hex"])
    for name, auth_data in auth_data_sources.items():
        for part, item in _auth_data_items(auth_data).items():
            items[f"{name}<{part}>"] = item

    unusable = [name for name, item in items.items() if _whole_item(item) is None]
    assert not unusable, unusable
    return items


def _ctap_literals() -> dict[str, bytes]:
    """Hex text under tests/, and hex or base64url in the golden records, that is a CTAP byte and one whole map."""

    found: dict[bytes, str] = {}

    def keep(data: bytes, where: str) -> None:
        if len(data) > 2 and (data[0] in COMMANDS or data[0] in STATUSES) and data[1] >> 5 == 5 and _whole_item(data[1:]):
            found.setdefault(data, where)

    for path in sorted(_TESTS.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.replace(" ", "")
                if _HEX.fullmatch(text):
                    keep(bytes.fromhex(text), f"literal:{text[:24]}")
    for path in sorted((_TESTS / "app" / "characterization").rglob("*.json")):
        for value in re.findall(r'"([0-9A-Za-z_+/=-]{8,})"', path.read_text(encoding="utf-8")):
            for data in _binary_readings(value):
                keep(data, f"golden:{path.stem}:{data.hex()[:16]}")
    return {where: data for data, where in found.items()}


def payloads() -> dict[str, str]:
    """Inputs that are not one well-formed item, as ``/api/codec`` is sent them: name -> payload.

    Each is one the codec once answered wrongly, which the round trips above,
    being of whole items, cannot hold.
    """

    return {
        # A getAssertion request whose second key is a tag around an indefinite-length
        # text string, read leniently: its first chunk is not UTF-8, the next three are
        # byte strings. Strictly it is refused at offset 22; leniently it answered 500.
        "getAssertion request: a key's text chunk that is not UTF-8": (
            "02:a2:a1:0d:a0:83:a1:83:d4:46:58:1b:c7:31:69:6e:d3:31:18:e8:2e:f3:fe:c0:7f:75:fd:15:96:d6:4f:f6:b3:2a:b0:"
            "eb:b7:40:6b:d6:2c:17:a3:48:65:b7:5f:41:4b:41:6f:41:ee:ff:f6:58:6a:db:af:45:68:35:46:94:a5:7a:bf:d3:5f:41:"
            "0f:41:3f:ff:1b:1b:b2:c0:08:d2:fc:02:52:d8:f5:84:a3:0b:16:cd:44:f6:e5:cf:e9:f3:67:61:74:74:53:74:6d:74:23:"
            "a4:b0:18:5c:1c:d8:28:9e:af:97:d2:5f:41:00:ff:63:66:6d:74:1b:74:93:8d:43:0b:04:dd:4e:f6:7f:a8:4f:c7:4d:ce:"
            "5f:41:c8:41:4f:41:26:84:f4:b9:c8:03:1b:1f:93:97:97:fc:8d:e4:1f:24:80:a1:83:5f:41:80:41:db:ff:fa:01:aa:68:"
            "9d:83:84:0b:5f:41:24:ff:50:1b:f2:b0:3d:2a:2e:91:5d:0a:1a:34:83:80:a0:0b:a0:a4:1b:25:df:a9:73:77:8b:6f:66:"
            "f7:43:8d:1b:5a:81:c8:02:d5:d6:bb:75:84:04:a1:07:80:07:a3:5f:ff:0d:64:6e:6f:6e:65:a0:64:6e:6f:6e:65:01:a0:"
            "a4:80:84:a4:09:d6:cb:5f:41:a9:41:2f:ff:1b:76:c0:cf:fb:2a:80:25:d2:63:66:6d:74:f4:72:dd:c4:8b:ff:71:c3:8a:"
            "f4:a1:04:37:d6:f9:07:a2:66:70:61:63:6b:65:64:51:f9:94:a1:d3:8b:83:32:78:6c:11:cb:82:81:a3:28:c0:8e:8c:f7:"
            "48:37:47:0d:b0:63:78:35:63:5f:41:b4:ff:26:a2:82:8e:dc:07:cc:11:a1:1b:e7:a1:5e:66:b7:19:97:8e:b2:64:80:81:"
            "82:05:a3:c4:67:61:74:74:53:74:6d:74:2b:27:52:67:61:74:74:53:74:6d:74:35:81:80:30"
        ),
        # Authenticator data whose extensions are 8(simple(1)): the simple value reached
        # the answer as a dataclass only Flask's JSON provider would write.
        "authenticator data: extensions holding a simple value": (
            "8480a1bc9c20070ca2ce83f722109f4c02a21a3f69fbca3c9f9fffa15106ff01819fff80d4c8e1"
        ),
        # So did the credential public key's: {1: 2, 3: -7, -1: undefined}.
        "authenticator data: a credential public key holding undefined": (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f41000000010000000000000000"
            "00000000000000000002aabba30102032620f7"
        ),
    }


@functools.cache
def ctap_messages() -> dict[str, bytes]:
    """Every CTAP message the repository holds, its command or status byte kept: name -> bytes.

    The corpus's items (a map sent without a CTAP byte), with every CTAP byte
    and item under tests/ and in the golden records. Which of them the decoder
    reads as a CTAP message is the decoder's to say.
    """

    messages = dict(corpus())
    for name, data in _ctap_literals().items():
        messages.setdefault(f"ctap:{name}", data)
    return messages
