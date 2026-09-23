"""The encoder writes CTAP2-canonical CBOR.

CTAP2 sorts map keys by major type first, then by encoded length, then
bytewise (CTAP 2.2 section 8, "CTAP2 canonical CBOR encoding form"). The
encoder used ``cbor2.dumps(canonical=True)``, which sorts RFC 7049 style,
length first, so ``{24: 0, "": 0}`` came out ``a2 6000 181800`` instead of
``a2 181800 6000``. The vendored ``fido2.cbor.encode``, which python-fido2 uses
to talk to real authenticators, is the reference these maps are compared with.
"""
from __future__ import annotations

import json
import random
from decimal import Decimal

import cbor2
import pytest

from fido2 import cbor
from server.app.decoder import encode_payload_text
from server.app.decoder.encode import cbor_canonical


def test_the_known_divergence_is_encoded_ctap2_canonically():
    assert cbor_canonical._canonical_cbor_dumps({24: 0, "": 0}).hex() == "a2181800" + "6000"
    assert cbor_canonical._canonical_cbor_dumps({"": 0, 24: 0}).hex() == "a2181800" + "6000"


def test_integer_keys_sort_unsigned_before_negative_whatever_their_length():
    # RFC 7049 puts -1 (one byte, 0x20) before 24 (two bytes, 0x1818).
    assert cbor_canonical._canonical_cbor_dumps({-1: 0, 24: 0}).hex() == "a2" + "181800" + "2000"


def test_the_display_order_matches_the_bytes():
    ordered = cbor_canonical._canonicalize_cbor_structure({"": 0, -1: 0, 24: 0, b"": 0})

    assert list(ordered) == [24, -1, b"", ""]


def _random_key(rng: random.Random):
    kind = rng.choice(("uint", "nint", "text", "bytes"))
    if kind == "uint":
        return rng.choice((rng.randrange(24), rng.randrange(24, 256), rng.randrange(256, 70000), rng.randrange(1 << 40)))
    if kind == "nint":
        return -1 - rng.choice((rng.randrange(24), rng.randrange(24, 256), rng.randrange(256, 70000)))
    size = rng.choice((0, 1, rng.randrange(2, 24), rng.randrange(24, 40)))
    if kind == "text":
        return "".join(rng.choice("abcxyz09") for _ in range(size))
    return bytes(rng.randrange(256) for _ in range(size))


def _random_value(rng: random.Random, depth: int):
    choices = ["int", "text", "bytes", "bool"]
    if depth < 3:
        choices += ["list", "map", "map"]
    kind = rng.choice(choices)
    if kind == "int":
        return rng.randrange(-70000, 70000)
    if kind == "text":
        return "".join(rng.choice("pqr") for _ in range(rng.randrange(30)))
    if kind == "bytes":
        return bytes(rng.randrange(256) for _ in range(rng.randrange(30)))
    if kind == "bool":
        return rng.choice((True, False))
    if kind == "list":
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    return _random_map(rng, depth + 1)


def _random_map(rng: random.Random, depth: int = 0) -> dict:
    return {_random_key(rng): _random_value(rng, depth) for _ in range(rng.randrange(1, 8))}


def _ctap2_reference(value) -> bytes:
    """An independent CTAP2 encoder: fido2 encodes the items, this orders the keys."""

    if isinstance(value, dict):
        items = sorted(
            ((_ctap2_reference(key), _ctap2_reference(item)) for key, item in value.items()),
            key=lambda pair: (pair[0][0] >> 5, len(pair[0]), pair[0]),
        )
        return cbor.dump_int(len(items), mt=5) + b"".join(key + item for key, item in items)
    if isinstance(value, list):
        return cbor.dump_int(len(value), mt=4) + b"".join(_ctap2_reference(item) for item in value)
    return cbor.encode(value)


def test_many_random_mixed_type_maps_encode_as_fido2_does():
    rng = random.Random(0xC7A2)
    maps = [_random_map(rng) for _ in range(500)]

    assert sum(len({type(key) for key in sample}) > 1 for sample in maps) > 300
    for sample in maps:
        expected = cbor.encode(sample)
        assert _ctap2_reference(sample) == expected
        assert cbor_canonical._canonical_cbor_dumps(sample) == expected, sample


def test_array_keys_sort_by_encoded_length_within_their_major_type():
    # [1000] is 81 19 03e8 (four bytes), [1, 2] is 82 01 02 (three): shorter first.
    encoded = cbor_canonical._canonical_cbor_dumps({(1000,): 0, (1, 2): 0})

    assert encoded.hex() == "a2" + "82010200" + "811903e800"


def test_no_ctap_message_is_serialised_by_cbor2(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("cbor2.dumps must not serialise encoder output")

    monkeypatch.setattr(cbor2, "dumps", refuse)

    result = encode_payload_text(
        json.dumps({"01": "example.com", "02": "22" * 32, "05": {"up": True}}),
        "CBOR (CTAP/WebAuthn Data)",
    )

    assert bytes.fromhex(result["data"]["binary"]["hex"]) == b"\x02" + cbor.encode(
        {1: "example.com", 2: b"\x22" * 32, 5: {"up": True}}
    )


def test_a_value_the_encoder_has_no_canonical_form_for_is_refused():
    with pytest.raises(ValueError, match="Decimal"):
        cbor_canonical._canonical_cbor_dumps({1: Decimal("1.5")})
