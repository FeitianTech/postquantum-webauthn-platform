from collections.abc import Mapping
from pathlib import Path
import sys

import pytest

import cbor2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from server.decoder.encode import _canonical_cbor_dumps


def test_canonical_cbor_sorts_map_keys_by_encoded_length_and_value():
    payload = {"aa": "aa", 1000: "big", "a": "a", 10: "ten"}

    encoded = _canonical_cbor_dumps(payload)

    # Map of four entries: 0xa4 followed by canonical key/value ordering.
    expected_hex = "a40a6374656e616161611903e863626967626161626161"
    assert encoded.hex() == expected_hex
    assert cbor2.loads(encoded) == {10: "ten", "a": "a", 1000: "big", "aa": "aa"}


def test_canonical_cbor_rejects_duplicate_keys_after_canonicalisation():
    class DuplicateMapping(Mapping):
        def __init__(self):
            self._items = [(b"a", 1), (memoryview(b"a"), 2)]

        def __iter__(self):
            for key, _ in self._items:
                yield key

        def __len__(self):
            return len(self._items)

        def __getitem__(self, key):  # pragma: no cover - required by Mapping
            for candidate, value in self._items:
                if candidate is key or candidate == key:
                    return value
            raise KeyError(key)

        def items(self):  # type: ignore[override]
            return list(self._items)

    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        _canonical_cbor_dumps(DuplicateMapping())


def test_canonical_cbor_encodes_floats_using_shortest_precision():
    encoded = _canonical_cbor_dumps([1.0, 1.5])

    # Array header (0x82) followed by canonical float16 encodings for 1.0 and 1.5.
    assert encoded[:4] == bytes.fromhex("82f93c00")
    assert encoded[4:] == bytes.fromhex("f93e00")
    decoded = cbor2.loads(encoded)
    assert decoded == [1.0, 1.5]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        True,
        False,
        0,
        1,
        23,
        24,
        255,
        256,
        -1,
        -24,
        -25,
        1.0,
        1.5,
        float("inf"),
        float("-inf"),
        "a",
        "aa",
        b"a",
        [1, 2, 3],
        {"a": 1, "b": 2},
        {"b": 1, "a": 2},
        {1: "one", 10: "ten"},
    ],
)
def test_canonical_cbor_matches_cbor2_canonical_output(payload):
    ours = _canonical_cbor_dumps(payload)
    theirs = cbor2.dumps(payload, canonical=True)
    assert ours == theirs
