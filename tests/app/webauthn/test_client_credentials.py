"""``webauthn.client_credentials``: a saved credential the page sends back, read into its key material."""

from __future__ import annotations

import pytest

from server.app import encoding
from server.app.webauthn import client_credentials

AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")


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
