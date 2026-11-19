"""``webauthn.client_credentials``: a saved credential the page sends back, read into its key material."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor, cose

from server.app import encoding
from server.app.webauthn import client_credentials
from tests.app.characterization import material

AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")
FIELDS = client_credentials.CredentialFields(aaguid=("aaguid",), credential_id=("credentialId",), public_key=("publicKey",))
MAX_KEY = client_credentials.MAX_PUBLIC_KEY_BYTES


def _entry(public_key: bytes) -> dict[str, str]:
    return {"aaguid": encoding.encode_base64url(AAGUID), "credentialId": "AAAA", "publicKey": encoding.encode_base64url(public_key)}


def _empty_maps(length: int) -> bytes:
    """A CBOR array of empty maps, ``length`` bytes long: what fido2's decoder reads slowest."""

    count = length - 5
    return b"\x9a" + count.to_bytes(4, "big") + b"\xa0" * count


@pytest.mark.parametrize("text", [AAGUID.hex(), AAGUID.hex(":"), AAGUID.hex().upper()])
def test_an_aaguid_named_hex_is_read_as_hex(text):
    assert client_credentials.read_aaguid("aaguidHex", text) == AAGUID


def test_an_aaguid_in_another_field_is_read_as_the_clients_bytes():
    assert client_credentials.read_aaguid("aaguid", encoding.encode_base64url(AAGUID)) == AAGUID
    assert client_credentials.read_aaguid(None, list(AAGUID), iterables=True) == AAGUID


def test_an_aaguid_named_hex_that_is_not_hex_is_refused():
    with pytest.raises(ValueError):
        client_credentials.read_aaguid("aaguidHex", "not hex at all")


def test_the_first_field_present_is_selected_with_its_name():
    entry = {"aaguidBase64": None, "aaguidHex": "00"}

    assert client_credentials.select_field(entry, ("aaguid", "aaguidBase64", "aaguidHex")) == ("aaguidHex", "00")
    assert client_credentials.select_field(entry, ("aaguidBase64", "aaguidHex"), skip_none=False) == ("aaguidBase64", None)
    assert client_credentials.select_field(entry, ("aaguid",)) == (None, None)


def test_first_value_skips_none_only_when_requested():
    values = {'first': None, 'second': 0, 'third': 'x'}
    assert client_credentials.select_first(values, ('first', 'second', 'third')) == 0
    assert client_credentials.select_first(values, ('first', 'second', 'third'), skip_none=False) is None


@pytest.mark.parametrize("key_type", ["ML-DSA-87", "ML-DSA-65", "ML-DSA-44", "ed25519", "es256", "rs256"])
def test_every_real_key_is_read(key_type):
    authenticator = material.Authenticator("saved", key_type=key_type)

    material_read = client_credentials.read_key_material(_entry(authenticator.cose_key_bytes), FIELDS)

    assert material_read.attested.public_key == authenticator.cose_key


def test_an_es384_key_is_read():
    key = cose.ES384.from_cryptography_key(ec.generate_private_key(ec.SECP384R1()).public_key())

    assert client_credentials.read_key_material(_entry(cbor.encode(dict(key))), FIELDS).attested.public_key == key


def test_the_largest_real_key_is_well_inside_the_cap():
    assert len(material.Authenticator("saved", key_type="ML-DSA-87").cose_key_bytes) * 3 < MAX_KEY


def test_a_key_longer_than_the_cap_is_refused_before_it_is_decoded(monkeypatch):
    def _unreached(_data):
        pytest.fail("fido2's decoder was handed a key longer than the cap")

    monkeypatch.setattr(cbor, "decode", _unreached)

    with pytest.raises(ValueError, match="longer than any real key"):
        client_credentials.read_key_material(_entry(_empty_maps(MAX_KEY + 1)), FIELDS)


def test_a_key_at_the_cap_is_decoded(monkeypatch):
    decoded: list[int] = []

    def _decode(data):
        decoded.append(len(data))
        raise ValueError("decoded")

    monkeypatch.setattr(cbor, "decode", _decode)

    with pytest.raises(ValueError, match="^decoded$"):
        client_credentials.read_key_material(_entry(_empty_maps(MAX_KEY)), FIELDS)
    assert decoded == [MAX_KEY]
