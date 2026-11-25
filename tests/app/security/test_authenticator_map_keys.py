"""A registration whose authenticator keys a map in a way JSON cannot sort completes on both tabs.

CBOR map keys may be byte strings, or integers beside text; fido2 accepts such extension
outputs and COSE key members. The Advanced tab writes those keys as text in its answer and
its stored artifact (``json_values.make_json_safe``'s ``writable_keys``), a byte string as
base64url, and stores nothing for a registration it then refuses. Maps JSON can already
write, keyed only by text or only by integers, keep their bytes.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from fido2 import cbor

from ..advanced.registration_ceremony import register
from .ceremony_helpers import Authenticator, complete_simple_registration

_COSE_KEY_INVALID = "cose_key_invalid: kty {b'k': 1} is not EC2 (2), the key type of COSE algorithm -7"


def _with_kty(authenticator: Authenticator, kty: Any) -> bytes:
    return cbor.encode({**authenticator.cose_key, 1: kty})


def _stored_record(advanced_storage: list[Any]) -> dict[str, Any]:
    (_storage_id, payload, _session_id), = advanced_storage
    # What the artifact store writes reads back as the same JSON.
    assert json.loads(json.dumps(payload)) == payload
    return payload["storedCredential"]


@pytest.mark.parametrize(
    "extensions, written",
    [
        (
            {"credProtect": 2, 1: 1},
            {"1": 1, "credProtect": 2, "credProtectLabel": "userVerificationOptionalWithCredentialIDList"},
        ),
        ({b"k": 1}, {"aw": 1}),
        ({"vendorExt": {1: 1, "a": 2}}, {"vendorExt": {"1": 1, "a": 2}}),
        ({"vendorExt": {b"k": 1}}, {"vendorExt": {"aw": 1}}),
    ],
)
def test_extension_outputs_keyed_by_bytes_or_mixed_types_complete_on_both_tabs(
    client, advanced_storage, simple_storage, extensions, written
):
    advanced = register(client, auth_data=lambda authenticator: authenticator.authenticator_data(extensions=extensions))

    assert advanced.status_code == 200, advanced.get_json()
    answer = json.loads(advanced.get_data(as_text=True))
    assert answer["relyingParty"]["registrationData"]["authenticatorExtensions"] == written
    assert answer["attestationErrors"] == []
    _stored_record(advanced_storage)

    simple = complete_simple_registration(client, Authenticator(), extensions=extensions)
    assert simple.status_code == 200, simple.get_json()


def test_a_cose_key_type_keyed_by_bytes_completes_with_its_finding(client, advanced_storage, simple_storage):
    advanced = register(client, auth_data=lambda authenticator: authenticator.authenticator_data(
        cose_key_bytes=_with_kty(authenticator, {b"k": 1})
    ))

    assert advanced.status_code == 200, advanced.get_json()
    answer = json.loads(advanced.get_data(as_text=True))
    assert answer["attestationErrors"] == [_COSE_KEY_INVALID]
    assert answer["storedCredential"]["publicKeyType"] == {"aw": 1}
    assert _stored_record(advanced_storage)["publicKeyType"] == {"aw": 1}

    # The Simple tab refuses the key on its integrity error, as it did.
    authenticator = Authenticator()
    simple = complete_simple_registration(client, authenticator, cose_key_bytes=_with_kty(authenticator, {b"k": 1}))
    assert simple.status_code == 400
    assert simple.get_json()["attestationErrors"] == [_COSE_KEY_INVALID]
    assert simple_storage == {}


def test_extension_outputs_keyed_only_by_integers_answer_as_they_did(client, advanced_storage):
    advanced = register(client, auth_data=lambda authenticator: authenticator.authenticator_data(
        extensions={"vendorExt": {2: 1, 10: 2, -1: 3}}
    ))

    assert advanced.status_code == 200, advanced.get_json()
    assert '"authenticatorExtensions":{"vendorExt":{"-1":3,"10":2,"2":1}}' in advanced.get_data(as_text=True)


@pytest.mark.parametrize(
    "kty, written",
    [
        ({2: 1, 10: 2, -1: 3}, '{"2": 1, "10": 2, "-1": 3}'),
        # Text beside a boolean, which JSON writes unsorted: the boolean as JSON spells it.
        ({True: 1, "a": 2}, '{"a": 2, "true": 1}'),
    ],
)
def test_cose_key_types_json_could_write_are_stored_as_they_were(client, advanced_storage, kty, written):
    advanced = register(client, auth_data=lambda authenticator: authenticator.authenticator_data(
        cose_key_bytes=_with_kty(authenticator, kty)
    ))

    assert advanced.status_code == 200, advanced.get_json()
    assert json.dumps(_stored_record(advanced_storage)["publicKeyType"]) == written
