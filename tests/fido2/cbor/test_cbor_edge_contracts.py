import pytest

from fido2 import cbor


def test_cbor_rejects_unsupported_values_and_extraneous_data():
    with pytest.raises(ValueError, match="Unsupported value"):
        cbor.encode(object())

    with pytest.raises(ValueError, match="Extraneous data"):
        cbor.decode(b"\x01\x02")