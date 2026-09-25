"""Every CBOR item the repository's tests and golden records hold, for the codec's round-trip tests.

Each entry is one whole, strictly well-formed item, named by where it came
from. Sources: the real device and specification vectors
(``tests/app/decoder/real_vectors.py``); the attestation objects the
characterization goldens are built from; registration responses built as the
golden scenarios build them; the vendored fido2 tests' CBOR vectors and CTAP
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
    from tests.app.characterization import material

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

    from tests.app.characterization import material
    from tests.app.decoder import real_vectors
    from tests.fido2.cbor.test_cbor import _TEST_VECTORS
    from tests.fido2.client.test_client import _MC_RESP as _CLIENT_MC_RESP

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
