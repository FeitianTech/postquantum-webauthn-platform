"""A ceremony response whose CBOR nests deeper or holds more items than ``cbor_bounds`` reads is
refused, on both tabs' registration and sign-in completes, before fido2's decoder is handed it;
one at the caps goes on to fido2."""
from __future__ import annotations

import hashlib
from typing import Any

import pytest
from fido2 import cbor

from server.app.webauthn import cbor_bounds
from tests.app.entry_app import entry_app

from .ceremony_helpers import (
    FLAG_AT,
    ORIGIN,
    SIMPLE_EMAIL,
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    attestation_object,
    b64u,
    begin_simple_registration,
    client_data,
    registration_payload,
    simple_complete_body,
    unb64u,
)

FLAG_ED = 0x80
# Every hostile value ends in a byte string this long: any decode of what holds it is handed more.
PADDING = 4096
# Items and levels around the value: an attestation object's map, with fmt, attStmt and authData.
AROUND = {"attestation-object": (8, 1), "credential-key": (0, 0), "extensions": (0, 0)}


def _value(placement: str, cap: str, past: bool) -> bytes:
    """CBOR at a cap, or one past it, where ``placement`` puts it, then the padding."""

    items, depth = AROUND[placement]
    padding = b"\x59" + PADDING.to_bytes(2, "big") + bytes(PADDING)
    if cap == cbor_bounds.DEPTH:
        return b"\x81" * (cbor_bounds.MAX_DEPTH - depth - 1 + int(past)) + padding
    count = cbor_bounds.MAX_ITEMS - items - 1 + int(past)
    return b"\x99" + count.to_bytes(2, "big") + b"\xa0" * (count - 1) + padding


def _authenticator_data(authenticator: Authenticator, placement: str, value: bytes, *, registration: bool) -> bytes:
    if placement == "credential-key":
        data = bytearray(authenticator.authenticator_data(include_credential=False))
        data[32] |= FLAG_AT
        cred = authenticator.credential_id
        return bytes(data) + authenticator.aaguid + len(cred).to_bytes(2, "big") + cred + value
    data = bytearray(authenticator.authenticator_data(include_credential=registration, counter=0 if registration else 1))
    if placement == "extensions":
        data[32] |= FLAG_ED
        data += value
    return bytes(data)


def _registration(authenticator: Authenticator, challenge: bytes, placement: str, value: bytes) -> dict[str, Any]:
    auth_data = _authenticator_data(authenticator, placement, value, registration=True)
    obj = attestation_object(auth_data)
    if placement == "attestation-object":
        obj = b"\xa4" + obj[1:] + cbor.encode("x") + value
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data(challenge=challenge, ceremony_type="webauthn.create")),
            "attestationObject": b64u(obj),
        },
        "clientExtensionResults": {},
    }


def _assertion(authenticator: Authenticator, challenge: bytes, placement: str, value: bytes) -> dict[str, Any]:
    auth_data = _authenticator_data(authenticator, placement, value, registration=False)
    data = client_data(challenge=challenge, ceremony_type="webauthn.get")
    response = assertion_payload(authenticator, challenge=challenge)
    response["response"].update(
        authenticatorData=b64u(auth_data),
        signature=b64u(authenticator.sign(auth_data + hashlib.sha256(data).digest())),
    )
    return response


def _simple_registration(client, authenticator, response_for):
    challenge = begin_simple_registration(client)
    return lambda placement, value: client.post(
        f"/api/register/complete?email={SIMPLE_EMAIL}",
        json=response_for(challenge, placement, value),
        headers={"Origin": ORIGIN},
    )


def _advanced_registration(client, authenticator, response_for):
    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return lambda placement, value: client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=challenge),
            "__credential_response": response_for(challenge, placement, value),
        },
        headers={"Origin": ORIGIN},
    )


def _simple_sign_in(client, authenticator, response_for):
    entry = authenticator.stored_credential_entry()
    begin = client.post(f"/api/authenticate/begin?email={SIMPLE_EMAIL}", json={"credentials": [entry]})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return lambda placement, value: client.post(
        f"/api/authenticate/complete?email={SIMPLE_EMAIL}",
        json=simple_complete_body(response_for(challenge, placement, value), [entry]),
        headers={"Origin": ORIGIN},
    )


def _advanced_sign_in(client, authenticator, response_for):
    entry = authenticator.stored_credential_entry()
    begin = client.post(
        "/api/advanced/authenticate/begin",
        json={"publicKey": {"challenge": {"$base64url": b64u(b"\x21" * 32)}}, "__storedCredentials": [entry]},
    )
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return lambda placement, value: client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [entry],
            "__assertion_response": response_for(challenge, placement, value),
        },
        headers={"Origin": ORIGIN},
    )


REGISTRATIONS = {"simple": _simple_registration, "advanced": _advanced_registration}
SIGN_INS = {"simple": _simple_sign_in, "advanced": _advanced_sign_in}
CASES = [
    *(
        ("registration", tab, placement, cap)
        for tab in REGISTRATIONS
        for placement in ("attestation-object", "credential-key", "extensions")
        for cap in (cbor_bounds.DEPTH, cbor_bounds.ITEMS)
    ),
    *(
        ("authentication", tab, placement, cap)
        for tab in SIGN_INS
        for placement in ("credential-key", "extensions")
        for cap in (cbor_bounds.DEPTH, cbor_bounds.ITEMS)
    ),
]


def _complete(ceremony: str, tab: str):
    """The complete of ``tab``'s ceremony, begun: it takes the placement and the value."""

    authenticator = Authenticator()
    if ceremony == "registration":
        return REGISTRATIONS[tab](entry_app().test_client(), authenticator, lambda c, p, v: _registration(authenticator, c, p, v))
    return SIGN_INS[tab](entry_app().test_client(), authenticator, lambda c, p, v: _assertion(authenticator, c, p, v))


def _sentence(ceremony: str, cap: str) -> str:
    what = (
        f"nests its CBOR more than {cbor_bounds.MAX_DEPTH} levels deep"
        if cap == cbor_bounds.DEPTH
        else f"holds more than {cbor_bounds.MAX_ITEMS:,} CBOR items"
    )
    return f"This {ceremony}'s response {what}, far more than any real one, so it was not read."


@pytest.fixture
def decoded_lengths(monkeypatch) -> list[int]:
    """The length of every input fido2's CBOR decoder is handed, at every level of its recursion."""

    lengths: list[int] = []
    decode, decode_from = cbor.decode, cbor.decode_from

    def _decode(data):
        lengths.append(len(data))
        return decode(data)

    def _decode_from(data):
        lengths.append(len(data))
        return decode_from(data)

    monkeypatch.setattr(cbor, "decode", _decode)
    monkeypatch.setattr(cbor, "decode_from", _decode_from)
    return lengths


@pytest.mark.parametrize(("ceremony", "tab", "placement", "cap"), CASES)
def test_a_response_past_a_cap_is_refused_before_fido2_decodes_it(
    ceremony, tab, placement, cap, decoded_lengths, simple_storage, advanced_storage
):
    complete = _complete(ceremony, tab)

    answer = complete(placement, _value(placement, cap, past=True))

    assert answer.status_code == 400
    assert answer.get_json()["error"] == _sentence(ceremony, cap)
    assert max(decoded_lengths, default=0) < PADDING


@pytest.mark.parametrize(("ceremony", "tab", "placement", "cap"), CASES)
def test_a_response_at_a_cap_goes_on_to_fido2(ceremony, tab, placement, cap, decoded_lengths, simple_storage, advanced_storage):
    complete = _complete(ceremony, tab)

    answer = complete(placement, _value(placement, cap, past=False))

    assert answer.get_json().get("error") != _sentence(ceremony, cap)
    assert max(decoded_lengths) > PADDING
    # Its other members are a real ceremony's: fido2 accepts what does not hold the key.
    assert answer.status_code == (400 if placement == "credential-key" else 200), answer.get_json()


@pytest.mark.parametrize(
    ("ceremony", "tab"), [("registration", "simple"), ("authentication", "simple"), ("authentication", "advanced")]
)
def test_a_refused_response_leaves_its_ceremony_to_complete(ceremony, tab, simple_storage, advanced_storage):
    authenticator = Authenticator()

    def _response(challenge, placement, value):
        if placement == "real":
            if ceremony == "registration":
                return registration_payload(authenticator, challenge=challenge)
            return assertion_payload(authenticator, challenge=challenge)
        return (_registration if ceremony == "registration" else _assertion)(authenticator, challenge, placement, value)

    client = entry_app().test_client()
    complete = (REGISTRATIONS if ceremony == "registration" else SIGN_INS)[tab](client, authenticator, _response)

    refused = complete("extensions", _value("extensions", cbor_bounds.DEPTH, past=True))
    answer = complete("real", b"")

    assert refused.status_code == 400
    assert answer.status_code == 200, answer.get_json()
