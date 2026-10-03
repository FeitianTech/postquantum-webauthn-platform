"""Tests for how the advanced routes read the credentials the page sends back."""
from __future__ import annotations

from server.app.routes.advanced import parsing
from tests.app.security.ceremony_helpers import Authenticator


def test_a_resident_flag_given_as_null_is_read_from_the_next_field_that_gives_one():
    said_by_cred_props = {
        **Authenticator(credential_id=b"\x01" * 32).stored_credential_entry(),
        "resident": None,
        "clientExtensionOutputs": {"credProps": {"rk": True}},
    }
    said_nowhere = {**Authenticator(credential_id=b"\x02" * 32).stored_credential_entry(), "resident": None}

    records = parsing._parse_client_supplied_credentials([said_by_cred_props, said_nowhere])

    assert [record["resident"] for record in records] == [True, False]


def test_an_aaguid_given_as_plain_hex_is_read_as_hex_not_as_base64():
    authenticator = Authenticator(credential_id=b"\x03" * 32, aaguid=bytes.fromhex("00112233445566778899aabbccddeeff"))
    entry = authenticator.stored_credential_entry()
    entry["aaguidHex"] = authenticator.aaguid.hex()
    del entry["aaguid"]

    records = parsing._parse_client_supplied_credentials([entry])

    assert [bytes(record["data"].aaguid) for record in records] == [authenticator.aaguid]
