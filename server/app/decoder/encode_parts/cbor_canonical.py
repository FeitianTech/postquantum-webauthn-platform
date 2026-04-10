"""Canonical CBOR serialization helpers for encoder flows."""
from __future__ import annotations

import math
import struct
from typing import Any, Dict, Iterable, List, Mapping, Tuple

import cbor2
from cbor2 import CBORTag, CBORSimpleValue, undefined


def _canonical_cbor_dumps(value: Any) -> bytes:
    """Serialize *value* using strict canonical CBOR rules."""

    return cbor2.dumps(value, canonical=True)


def _canonicalize_cbor_structure(value: Any) -> Any:
    """Return a structure whose maps follow canonical CBOR key ordering."""

    encoder = _CanonicalCBOREncoder()
    return encoder.canonicalize_structure(value)


class _CanonicalCBOREncoder:
    """Minimal canonical CBOR encoder specialised for deterministic output."""

    def encode(self, value: Any) -> bytes:
        return self._encode(value)

    def canonicalize_structure(self, value: Any) -> Any:
        return self._canonicalize(value)

    def _encode(self, value: Any) -> bytes:
        if isinstance(value, Mapping):
            return self._encode_map(value)
        if isinstance(value, CBORSimpleValue):
            return self._encode_cbor_simple_value(value)
        if isinstance(value, (list, tuple)):
            return self._encode_array(value)
        if isinstance(value, CBORTag):
            return self._encode_tag(value)
        return self._encode_simple(value)

    def _canonicalize(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return self._canonicalize_map(value)
        if isinstance(value, (list, tuple)):
            return [self._canonicalize(item) for item in value]
        if isinstance(value, CBORTag):
            return CBORTag(value.tag, self._canonicalize(value.value))
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        return value

    def _encode_simple(self, value: Any) -> bytes:
        if isinstance(value, bool):
            return b"\xf5" if value else b"\xf4"
        if value is None:
            return b"\xf6"
        if value is undefined:
            return b"\xf7"
        if isinstance(value, int):
            return self._encode_int(value)
        if isinstance(value, float):
            return _encode_canonical_float(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return self._encode_bytes(value)
        if isinstance(value, str):
            return self._encode_text(value)
        if isinstance(value, CBORSimpleValue):
            return self._encode_cbor_simple_value(value)

        # Fall back to cbor2 for less common types (e.g. decimal.Decimal, datetime).
        # The canonical flag preserves determinism while allowing extended values.
        return cbor2.dumps(value, canonical=True)

    def _encode_array(self, values: Iterable[Any]) -> bytes:
        encoded_items = [self._encode(item) for item in values]
        prefix = _encode_major_type_with_length(4, len(encoded_items))
        return prefix + b"".join(encoded_items)

    def _encode_bytes(self, value: Any) -> bytes:
        data = bytes(value)
        prefix = _encode_major_type_with_length(2, len(data))
        return prefix + data

    def _encode_map(self, mapping: Mapping[Any, Any]) -> bytes:
        sorted_items = self._sorted_map_items(mapping)
        prefix = _encode_major_type_with_length(5, len(sorted_items))
        chunks = []
        for encoded_key, _original_key, value in sorted_items:
            encoded_value = self._encode(value)
            chunks.append(encoded_key + encoded_value)
        return prefix + b"".join(chunks)

    def _canonicalize_map(self, mapping: Mapping[Any, Any]) -> Dict[Any, Any]:
        sorted_items = self._sorted_map_items(mapping)
        result: Dict[Any, Any] = {}
        for _encoded_key, key, value in sorted_items:
            result[key] = self._canonicalize(value)
        return result

    def _sorted_map_items(
        self, mapping: Mapping[Any, Any]
    ) -> List[Tuple[bytes, Any, Any]]:
        encoded_items: List[Tuple[bytes, Any, Any]] = []
        seen_keys: set[bytes] = set()
        for key, value in mapping.items():
            encoded_key = self._encode(key)
            if encoded_key in seen_keys:
                raise ValueError(
                    "Duplicate CBOR map key detected during canonical encoding."
                )
            seen_keys.add(encoded_key)
            encoded_items.append((encoded_key, key, value))

        encoded_items.sort(key=lambda item: (len(item[0]), item[0]))
        return encoded_items

    def _encode_tag(self, tag: CBORTag) -> bytes:
        if not isinstance(tag.tag, int) or tag.tag < 0:
            raise ValueError("CBOR tags must be non-negative integers.")
        encoded_tag = _encode_unsigned_integer(6, tag.tag)
        encoded_value = self._encode(tag.value)
        return encoded_tag + encoded_value

    def _encode_int(self, value: int) -> bytes:
        if value >= 0:
            return _encode_unsigned_integer(0, value)

        complement = -1 - value
        return _encode_unsigned_integer(1, complement)

    def _encode_text(self, value: str) -> bytes:
        data = value.encode("utf-8")
        prefix = _encode_major_type_with_length(3, len(data))
        return prefix + data

    def _encode_cbor_simple_value(self, value: CBORSimpleValue) -> bytes:
        simple = value.value
        if not isinstance(simple, int):
            raise TypeError("CBOR simple value code must be an integer.")
        if simple < 0 or simple > 255:
            raise ValueError("CBOR simple value code must be between 0 and 255.")

        if simple <= 23:
            return bytes([0xE0 | simple])
        if 32 <= simple <= 255:
            return b"\xf8" + bytes([simple])

        raise ValueError("CBOR simple values 24..31 are reserved in canonical encoding.")


def _encode_major_type_with_length(major_type: int, length: int) -> bytes:
    if length < 0:
        raise ValueError("CBOR lengths must be non-negative.")
    return _encode_unsigned_integer(major_type, length)


def _encode_unsigned_integer(major_type: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("Unsigned CBOR integers must be non-negative.")

    if value < 24:
        return bytes([(major_type << 5) | value])
    if value < 256:
        return bytes([(major_type << 5) | 24, value])
    if value < 65536:
        return bytes([(major_type << 5) | 25]) + value.to_bytes(2, "big")
    if value < 4294967296:
        return bytes([(major_type << 5) | 26]) + value.to_bytes(4, "big")
    if value < 18446744073709551616:
        return bytes([(major_type << 5) | 27]) + value.to_bytes(8, "big")

    raise ValueError("CBOR integers exceeding 64 bits are not supported in canonical mode.")


def _encode_canonical_float(value: float) -> bytes:
    if math.isnan(value):
        # Canonical NaN representation (RFC 8949, Section 3.9): 0xf9 7e00
        return b"\xf9\x7e\x00"

    for fmt, prefix in (("e", b"\xf9"), ("f", b"\xfa"), ("d", b"\xfb")):
        try:
            packed = struct.pack(">" + fmt, value)
        except (OverflowError, ValueError):
            continue

        unpacked = struct.unpack(">" + fmt, packed)[0]
        if math.isnan(unpacked):
            continue

        if unpacked == value and math.copysign(1.0, unpacked) == math.copysign(1.0, value):
            return prefix + packed

    # Fall back to float64 encoding when no shorter representation is exact.
    return b"\xfb" + struct.pack(">d", value)
