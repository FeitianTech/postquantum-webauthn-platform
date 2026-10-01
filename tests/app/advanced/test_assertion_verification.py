"""Tests for how advanced authenticate complete reports fido2's verification."""
from __future__ import annotations

from types import SimpleNamespace

from server.app.routes.advanced import assertion_verification
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, assertion_payload

from .assertion_ceremony import CHALLENGE, begin, complete


class _GettableKey:
    def get(self, label):
        return {3: -7}.get(label)


class _UnreadableKey:
    def get(self, label):
        raise TypeError("this key cannot be read")


def test_an_assertion_without_a_credential_id_fails_without_naming_one():
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    client = entry_app().test_client()
    begin(client, credentials)
    assertion = assertion_payload(authenticator, challenge=CHALLENGE)
    del assertion["id"], assertion["rawId"]

    response = complete(client, credentials, assertion)

    assert response.status_code == 400
    body = response.get_json()
    assert body["status"] == "VERIFICATION_FAILED"
    assert body["verified"] is False
    assert "failedCredentialId" not in body
    assert "algorithm" not in body


def test_the_algorithm_is_read_from_the_credentials_own_key():
    def record(public_key):
        return {"data": SimpleNamespace(public_key=public_key)}

    assert assertion_verification._credential_cose_algorithm(record({3: -8})) == -8
    assert assertion_verification._credential_cose_algorithm(record(_GettableKey())) == -7
    assert assertion_verification._credential_cose_algorithm(record(_UnreadableKey())) is None
    assert assertion_verification._credential_cose_algorithm(record({3: "ES256"})) is None
    assert assertion_verification._credential_cose_algorithm(record(None)) is None
    assert assertion_verification._credential_cose_algorithm(None) is None


def test_only_an_algorithm_fido2_has_a_key_class_for_is_supported():
    assert assertion_verification._server_supports_algorithm(-7) is True
    assert assertion_verification._server_supports_algorithm(-65000) is False
    assert assertion_verification._server_supports_algorithm("ES256") is False


def test_the_verified_algorithm_is_read_from_the_result_key_if_it_reads():
    assert assertion_verification._result_algorithm(SimpleNamespace(public_key={3: -8})) == -8
    assert assertion_verification._result_algorithm(SimpleNamespace(public_key=_GettableKey())) == -7
    assert assertion_verification._result_algorithm(SimpleNamespace(public_key=_UnreadableKey())) is None
    assert assertion_verification._result_algorithm(SimpleNamespace(public_key=None)) is None
