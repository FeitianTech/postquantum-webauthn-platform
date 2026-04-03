from collections import UserDict
from dataclasses import dataclass, field
import hashlib
from typing import Mapping, Optional, Sequence

import pytest

from fido2 import utils


@dataclass(eq=False, frozen=True)
class _DemoMapping(utils._DataClassMapping[str]):
    plain: Optional[int] = None
    encoded: Optional[int] = field(
        default=None,
        metadata={"serialize": lambda value: f"v:{value}"},
    )
    nested_map: Optional[Mapping[str, int]] = None
    list_of_maps: Optional[Sequence[Mapping[str, int]]] = None

    @classmethod
    def _get_field_key(cls, field):
        return field.name


@dataclass(eq=False, frozen=True)
class _ParseFail(utils._DataClassMapping[str]):
    count: int

    @classmethod
    def _get_field_key(cls, field):
        return field.name


def test_hash_helpers_and_algorithm_dispatch_cover_all_supported_and_error_paths():
    data = b"abc"

    assert utils.sha512(data) == hashlib.sha512(data).digest()
    assert utils.sha384(data) == hashlib.sha384(data).digest()
    assert utils.sha1(data) == hashlib.sha1(data).digest()
    assert utils.sha3_256(data) == hashlib.sha3_256(data).digest()
    assert utils.sha3_384(data) == hashlib.sha3_384(data).digest()
    assert utils.sha3_512(data) == hashlib.sha3_512(data).digest()

    assert utils.hash_with_algorithm(data, "SHA-512") == hashlib.sha512(data).digest()
    assert utils.hash_with_algorithm(data, "SHA-384") == hashlib.sha384(data).digest()
    assert utils.hash_with_algorithm(data, "SHA-1") == hashlib.sha1(data).digest()
    assert utils.hash_with_algorithm(data, "SHA3-256") == hashlib.sha3_256(data).digest()
    assert utils.hash_with_algorithm(data, "SHA3-384") == hashlib.sha3_384(data).digest()
    assert utils.hash_with_algorithm(data, "SHA3-512") == hashlib.sha3_512(data).digest()

    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        utils.hash_with_algorithm(data, "MD5")


def test_dataclass_mapping_getitem_serialization_and_error_contracts():
    sample = _DemoMapping(
        plain=7,
        encoded=9,
        nested_map=UserDict({"a": 1}),
        list_of_maps=[UserDict({"b": 2})],
    )

    assert sample["plain"] == 7
    assert sample["encoded"] == "v:9"
    assert sample["nested_map"] == {"a": 1}
    assert sample["list_of_maps"] == [{"b": 2}]

    missing = _DemoMapping(plain=None)
    with pytest.raises(KeyError):
        _ = missing["plain"]


def test_dataclass_mapping_parse_and_from_dict_edge_failures():
    with pytest.raises(ValueError, match="Error parsing field count"):
        _ParseFail(count="not-an-int")

    with pytest.raises(TypeError, match="non-Mapping data"):
        _DemoMapping.from_dict("not-a-mapping")
