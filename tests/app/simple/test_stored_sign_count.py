"""``routes.simple.stored_sign_count``: the counter an assertion is checked against, read
from the server's record and the browser's copy (the routes' checks are
``security/test_sign_count_regression.py``'s and ``security/test_sign_count_race.py``'s)."""
from __future__ import annotations

import hashlib

from fido2.webauthn import AuthenticatorData

from server.app.routes.simple import stored_sign_count
from tests.app.security.ceremony_helpers import RP_ID, Authenticator, b64u


def test_a_record_names_its_credential_by_its_own_id_or_else_its_credential_datas_bytes():
    registered = AuthenticatorData(Authenticator(credential_id=b"\x07" * 16).authenticator_data())

    assert stored_sign_count.record_credential_id({"credential_id": b"\x08" * 16}) == b"\x08" * 16
    assert stored_sign_count.record_credential_id({"credential_data": registered.credential_data}) == b"\x07" * 16
    assert stored_sign_count.record_credential_id({"credential_id": "not bytes"}) is None
    assert stored_sign_count.record_credential_id(["not", "a", "record"]) is None
    assert stored_sign_count.record_credential_id({}) is None


def test_a_record_stored_whole_keeps_only_what_the_counter_check_reads_with_its_time_and_handle():
    registered = AuthenticatorData(Authenticator(credential_id=b"\x07" * 16).authenticator_data(counter=4))
    whole = {
        "credential_data": registered.credential_data,
        "auth_data": registered,
        "user_info": {"name": "user@example.com", "user_handle": b"handle"},
        "registration_time": 1.5,
        "attestation_object": "o2NmbXRkbm9uZQ",
        "properties": {"attestationChecks": {}},
    }
    slim = {"credential_id": b"\x07" * 16, "sign_count": 4, "registration_time": 1.5, "user_handle": b"handle"}

    assert stored_sign_count.as_counter_record(whole) == slim
    assert stored_sign_count.as_counter_record({**whole, "sign_count": 9})["sign_count"] == 9
    # Brought to that form once, it stays as it is.
    assert stored_sign_count.as_counter_record(slim) == slim
    assert stored_sign_count.counter_record(b"\x07" * 16, 4, 1.5, b"handle") == slim


def test_a_record_whose_credential_cannot_be_read_is_kept_as_it_is():
    unreadable = {"credential_data": b"degraded to its bytes", "sign_count": 3}

    assert stored_sign_count.as_counter_record(unreadable) is unreadable
    assert stored_sign_count.as_counter_record("not a record") == "not a record"


def test_a_record_without_a_counter_of_its_own_has_its_authenticator_datas():
    auth_data = AuthenticatorData.create(hashlib.sha256(RP_ID.encode()).digest(), 0x01, 7)

    assert stored_sign_count.record_sign_count({"sign_count": 9, "auth_data": auth_data}) == 9
    assert stored_sign_count.record_sign_count({"sign_count": True, "auth_data": auth_data}) == 7
    assert stored_sign_count.record_sign_count({}) is None


def test_the_browsers_counter_is_read_only_from_an_entry_naming_the_credential():
    entries = [
        "not an entry",
        {"signCount": 9},
        {"credentialId": 12.5, "signCount": 9},
        {"credentialId": b64u(b"another credential"), "signCount": 9},
    ]

    assert stored_sign_count.client_supplied_sign_count(entries, b"this credential") is None
    assert stored_sign_count.client_supplied_sign_count(
        [*entries, {"credentialId": b64u(b"this credential"), "signCount": 4}], b"this credential"
    ) == 4
