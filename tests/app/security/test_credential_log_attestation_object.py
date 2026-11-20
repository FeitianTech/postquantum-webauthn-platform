"""A registration's credential log entry holds its attestation object as the server read it.

fido2 2.2.1 reads a byte of major type 7 alone and refuses tags; cbor2 reads the eight bytes
of a double after it and resolves shared values (tags 28 and 29). With the log on, both tabs
queue an entry for each registration they save, inside its request: at beb15ad6 the entry
decoded the attestation object again with cbor2 and wrote each shared value out in full,
2**levels leaves (20 levels cost 9.6 s and 907 MiB from 464 bytes that both tabs accept).
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from server.app.storage import github_mirror, github_outbox
from tests.app.storage import fake_github

from ..entry_app import entry_app
from .ceremony_helpers import (
    ORIGIN,
    SIMPLE_EMAIL,
    Authenticator,
    advanced_public_key_options,
    b64u,
    registration_payload,
    shared_where_fido2_reads_plain_items,
    unb64u,
)

# The real one: the storage fixtures turn it off.
RECORD_REGISTRATION_EVENT = github_mirror.record_registration_event


def _registered_by_simple(client, credential: Any) -> Any:
    begin = client.post(f"/api/register/begin?email={SIMPLE_EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return client.post(
        f"/api/register/complete?email={SIMPLE_EMAIL}", json=credential(challenge), headers={"Origin": ORIGIN}
    )


def _registered_by_advanced(client, credential: Any) -> Any:
    public_key = advanced_public_key_options(challenge=b"\x5a" * 32)
    begin = client.post("/api/advanced/register/begin", json={"publicKey": public_key})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    body = {"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": credential(challenge)}
    return client.post("/api/advanced/register/complete", json=body, headers={"Origin": ORIGIN})


@pytest.mark.parametrize("register", [_registered_by_simple, _registered_by_advanced])
def test_a_registration_logs_its_attestation_object_as_fido2_read_it(
    register, monkeypatch, simple_storage, advanced_storage
):
    fake_github.install(monkeypatch)
    monkeypatch.setattr(github_mirror, "record_registration_event", RECORD_REGISTRATION_EVENT)
    queued: list[github_outbox.OutboxEntry] = []
    monkeypatch.setattr(github_outbox, "enqueue", lambda entries: queued.extend(entries) or 0)
    authenticator = Authenticator()
    attestation_object = shared_where_fido2_reads_plain_items(authenticator.authenticator_data(), levels=12)

    def credential(challenge: bytes) -> dict:
        payload = registration_payload(authenticator, challenge=challenge)
        payload["response"]["attestationObject"] = b64u(attestation_object)
        return payload

    response = register(entry_app().test_client(), credential)

    assert response.status_code == 200, response.get_json()
    [entry] = queued
    # Its shared value is not written out: cbor2's reading took 323 KB of JSON.
    assert len(entry.content) < 2048
    decoded = json.loads(entry.content)["decoded_attestation_object"]
    assert sorted(decoded) == ["1", "attStmt", "authData", "fmt", "x"]
    assert decoded["x"] is False
