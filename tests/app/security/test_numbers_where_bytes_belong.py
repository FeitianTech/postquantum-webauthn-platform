"""A number where fido2 reads bytes is refused before anything allocates that many.

fido2 2.2.1 makes a member it declares as bytes of any value that is not text by wrapping
it in the type: a JSON number N becomes N zero bytes. Every ceremony complete refuses such
a response with a 400 and one sentence, before the ceremony's state is read (the Advanced
registration, which consumes its state first by design, after it), and traced memory stays
far below the number (at 074e395a these cost 48 to 175 MiB each).
"""
from __future__ import annotations

import json
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest
from fido2 import cbor

from ..entry_app import entry_app
from .ceremony_helpers import (
    ORIGIN,
    SIMPLE_EMAIL,
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    attestation_object,
    b64u,
    registration_payload,
    unb64u,
)

# Tens of millions: enough to see fido2's allocation, never enough to hurt the machine running the tests.
NUMBER = 50_000_000
MIB = 1024 * 1024


def _traced(post: Callable[[], Any]) -> tuple[Any, int]:
    tracemalloc.start()
    try:
        response = post()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return response, peak


def _client_data(ceremony_type: str) -> str:
    return b64u(json.dumps({"type": ceremony_type, "challenge": NUMBER, "origin": ORIGIN}).encode())


def _safetynet(*, nonce: Any, x5c: list) -> str:
    header = b64u(json.dumps({"alg": "RS256", "x5c": x5c}).encode())
    payload = b64u(json.dumps({"ctsProfileMatch": True, "nonce": nonce}).encode())
    statement = {"ver": "1", "response": f"{header}.{payload}.c2ln".encode()}
    return b64u(attestation_object(Authenticator().authenticator_data(), fmt="android-safetynet", att_stmt=statement))


REGISTRATION_NUMBERS = [
    ({"rawId": NUMBER, "id": NUMBER}, "rawId must be text, not a number."),
    ({"clientDataJSON": NUMBER}, "response.clientDataJSON must be text, not a number."),
    ({"attestationObject": NUMBER}, "response.attestationObject must be text, not a number."),
    ({"clientDataJSON": _client_data("webauthn.create")}, "response.clientDataJSON's challenge must be text, not a number."),
    (
        {"attestationObject": b64u(cbor.encode({"fmt": "none", "attStmt": {}, "authData": NUMBER}))},
        "response.attestationObject's authData must be a byte string, not a number.",
    ),
    (
        {"attestationObject": _safetynet(nonce=NUMBER, x5c=[])},
        "response.attestationObject's android-safetynet response's nonce must be text, not a number.",
    ),
    (
        {"attestationObject": _safetynet(nonce="bm9uY2U", x5c=[NUMBER])},
        "response.attestationObject's android-safetynet response's x5c[0] must be text, not a number.",
    ),
]

AUTHENTICATION_NUMBERS = [
    ({"rawId": NUMBER, "id": NUMBER}, "rawId must be text, not a number."),
    ({"clientDataJSON": NUMBER}, "response.clientDataJSON must be text, not a number."),
    ({"authenticatorData": NUMBER}, "response.authenticatorData must be text, not a number."),
    ({"signature": NUMBER}, "response.signature must be text, not a number."),
    ({"userHandle": NUMBER}, "response.userHandle must be text, not a number."),
    ({"clientDataJSON": _client_data("webauthn.get")}, "response.clientDataJSON's challenge must be text, not a number."),
]


def _with(credential: dict, changes: dict) -> dict:
    for name, value in changes.items():
        (credential if name in ("rawId", "id") else credential["response"])[name] = value
    return credential


def _simple_registration(client, changes: dict) -> Any:
    begin = client.post(f"/api/register/begin?email={SIMPLE_EMAIL}", json={"credentials": []})
    credential = registration_payload(Authenticator(), challenge=unb64u(begin.get_json()["publicKey"]["challenge"]))
    return client.post(f"/api/register/complete?email={SIMPLE_EMAIL}", json=_with(credential, changes), headers={"Origin": ORIGIN})


def _advanced_registration(client, changes: dict) -> Any:
    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    credential = registration_payload(Authenticator(), challenge=challenge)
    body = {"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": _with(credential, changes)}
    return client.post("/api/advanced/register/complete", json=body, headers={"Origin": ORIGIN})


def _simple_authentication(client, changes: dict) -> Any:
    authenticator = Authenticator()
    entry = authenticator.stored_credential_entry()
    begin = client.post(f"/api/authenticate/begin?email={SIMPLE_EMAIL}", json={"credentials": [entry]})
    credential = assertion_payload(authenticator, challenge=unb64u(begin.get_json()["publicKey"]["challenge"]))
    body = {"credential": _with(credential, changes), "credentials": [entry]}
    return client.post(f"/api/authenticate/complete?email={SIMPLE_EMAIL}", json=body, headers={"Origin": ORIGIN})


def _advanced_authentication(client, changes: dict) -> Any:
    authenticator = Authenticator()
    entry = authenticator.stored_credential_entry()
    public_key = {"challenge": {"$base64url": b64u(b"\x71" * 32)}}
    client.post("/api/advanced/authenticate/begin", json={"publicKey": public_key, "__storedCredentials": [entry]})
    credential = assertion_payload(authenticator, challenge=b"\x71" * 32)
    body = {"publicKey": public_key, "__assertion_response": _with(credential, changes), "__storedCredentials": [entry]}
    return client.post("/api/advanced/authenticate/complete", json=body, headers={"Origin": ORIGIN})


CASES = [
    (complete, changes, sentence)
    for completes, numbers in (
        ((_simple_registration, _advanced_registration), REGISTRATION_NUMBERS),
        ((_simple_authentication, _advanced_authentication), AUTHENTICATION_NUMBERS),
    )
    for complete in completes
    for changes, sentence in numbers
]


@pytest.mark.parametrize(
    ("complete", "changes", "sentence"), CASES, ids=[f"{c.__name__}-{s}" for c, _changes, s in CASES]
)
def test_a_complete_refuses_a_number_where_bytes_belong_before_allocating_it(
    complete, changes, sentence, simple_storage, advanced_storage
):
    client = entry_app().test_client()

    response, peak = _traced(lambda: complete(client, changes))

    assert response.status_code == 400
    assert response.get_json()["error"] == sentence
    assert peak < 4 * MIB


def test_a_simple_registration_refused_for_a_number_keeps_its_challenge(simple_storage):
    client = entry_app().test_client()
    authenticator = Authenticator()
    begin = client.post(f"/api/register/begin?email={SIMPLE_EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    refused = registration_payload(authenticator, challenge=challenge)
    refused["rawId"] = refused["id"] = NUMBER

    assert client.post(f"/api/register/complete?email={SIMPLE_EMAIL}", json=refused, headers={"Origin": ORIGIN}).status_code == 400
    completed = client.post(
        f"/api/register/complete?email={SIMPLE_EMAIL}",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )
    assert completed.status_code == 200, completed.get_json()
