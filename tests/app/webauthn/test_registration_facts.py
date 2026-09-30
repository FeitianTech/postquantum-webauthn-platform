"""``webauthn.registration_facts``: what a verified registration says, one way for both tabs."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from server.app.encoding import encode_base64url
from server.app.webauthn import registration_facts

AAGUID = bytes.fromhex("2fc0579f811347eab116bb5a8db9202a")


def test_a_sixteen_byte_aaguid_has_its_hex_and_guid():
    aaguid_bytes, aaguid_hex, aaguid_guid = registration_facts.aaguid_values(SimpleNamespace(aaguid=AAGUID))

    assert aaguid_bytes == AAGUID
    assert aaguid_hex == AAGUID.hex()
    assert aaguid_guid == "2fc0579f-8113-47ea-b116-bb5a8db9202a"


@pytest.mark.parametrize(
    ("aaguid", "expected_bytes"),
    [
        (b"\x01\x02\x03\x04", b"\x01\x02\x03\x04"),  # not an AAGUID's length
        (None, None),
        (object(), None),  # not bytes at all
    ],
)
def test_an_aaguid_that_is_not_sixteen_bytes_has_no_hex_or_guid(aaguid, expected_bytes):
    assert registration_facts.aaguid_values(SimpleNamespace(aaguid=aaguid)) == (expected_bytes, None, None)


def test_an_aaguid_without_spellings_adds_nothing_to_the_record():
    properties = {}

    registration_facts.record_aaguid(properties, None, None)

    assert properties == {}


def test_the_rp_id_hash_report_puts_authdata_beside_the_expected_hash():
    expected = hashlib.sha256(b"example.com").digest()

    report = registration_facts.rp_id_hash_report(SimpleNamespace(rp_id_hash=expected), "example.com")

    assert report["bytes"] == report["expectedBytes"] == expected
    assert report["hex"] == report["expectedHex"] == expected.hex()
    assert report["base64url"] == report["expectedBase64url"] == encode_base64url(expected)


def test_an_rp_id_hash_that_is_not_bytes_is_reported_empty_and_only_the_expected_one_recorded():
    report = registration_facts.rp_id_hash_report(SimpleNamespace(rp_id_hash=object()), "example.com")
    properties = {}

    registration_facts.record_rp_id_hash(properties, report)

    assert (report["bytes"], report["hex"], report["base64url"]) == (b"", "", "")
    assert properties == {
        "rpIdHashExpected": report["expectedHex"],
        "rpIdHashExpectedBase64": report["expectedBase64url"],
    }


def test_the_relying_party_view_leaves_out_what_a_tab_does_not_give():
    rp_hash = registration_facts.rp_id_hash_report(SimpleNamespace(rp_id_hash=b""), "example.com")

    info = registration_facts.relying_party_info(
        aaguid=None,
        attestation_format="none",
        created_at="2026-09-30T00:00:00Z",
        credential_id={"hex": "01", "base64": "AQ==", "base64url": "AQ"},
        rp_hash=rp_hash,
        rp_id_hash_match=False,
        authenticator_data_hash="hash",
        large_blob=False,
        public_key_algorithm=-7,
        registration={},
        user_handle=b"\x01",
    )

    for key in ("aaguid", "attestationObject", "device", "residentKey", "attestationCertificate", "attestationCertificates"):
        assert key not in info
    assert info["userHandle"] == {"base64": "AQ==", "base64url": "AQ", "hex": "01"}


def test_a_stored_credential_keeps_its_fields_in_one_order_and_refuses_unknown_ones():
    fields = {"signCount": 0, "type": "public-key", "email": None}

    assert list(registration_facts.stored_credential(fields)) == ["type", "email", "signCount"]
    assert list(registration_facts.stored_credential(fields, drop_none=True)) == ["type", "signCount"]
    with pytest.raises(ValueError, match="not a stored credential field: \\['colour'\\]"):
        registration_facts.stored_credential({"colour": "blue"})
