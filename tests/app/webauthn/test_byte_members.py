"""``webauthn.byte_members``: a number where fido2 reads bytes, found before fido2 reads it.

The positions are enumerated from fido2's own declared types, so a member a fido2 release
adds is tested too; the expected lists say which positions that is today.
"""

from __future__ import annotations

import dataclasses
import json
import typing
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from fido2 import cbor
from fido2.mds3 import MetadataBlobPayloadEntry
from fido2.webauthn import AuthenticationResponse, RegistrationResponse

from server.app.webauthn import byte_members
from tests.app.security.ceremony_helpers import (
    Authenticator,
    assertion_payload,
    attestation_object,
    b64u,
    registration_payload,
)

NUMBER = 50_000_000
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "mds"


def _bytes_positions(cls: type, prefix: tuple = ()) -> list[tuple]:
    """Every position where ``cls`` declares bytes, as fido2's ``_parse_value`` follows its types."""

    hints = typing.get_type_hints(cls)
    positions: list[tuple] = []
    for field in dataclasses.fields(cls):
        positions += _declared_positions(hints[field.name], prefix + (cls._get_field_key(field),))
    return positions


def _declared_positions(declared, path: tuple) -> list[tuple]:
    if typing.get_origin(declared) in (typing.Union, type(int | None)):
        declared = typing.get_args(declared)[0]
    origin = typing.get_origin(declared)
    if isinstance(declared, type) and issubclass(declared, bytes):
        return [path]
    if dataclasses.is_dataclass(declared) and hasattr(declared, "from_dict"):
        return _bytes_positions(declared, path)
    if origin is not None and issubclass(origin, Mapping):
        return _declared_positions(typing.get_args(declared)[1], path + ("member",))
    if origin is not None and issubclass(origin, Sequence):
        return _declared_positions(typing.get_args(declared)[0], path + (0,))
    return []


def _spelled(path: tuple) -> str:
    text = ""
    for part in path:
        text += f"[{part}]" if isinstance(part, int) else (f".{part}" if text else part)
    return text


def _holding(path: tuple, value) -> dict:
    """A JSON value with ``value`` at ``path`` and nothing else."""

    root: dict = {}
    container = root
    for part, after in zip(path, path[1:] + (None,)):
        child = value if after is None else ([] if isinstance(after, int) else {})
        if isinstance(part, int):
            container.append(child)
        else:
            container[part] = child
        container = child
    return root


REGISTRATION = ["rawId", "response.clientDataJSON", "response.attestationObject"]
AUTHENTICATION = [
    "rawId",
    "response.clientDataJSON",
    "response.authenticatorData",
    "response.signature",
    "response.userHandle",
]
METADATA_ENTRY = [
    "aaguid",
    "attestationCertificateKeyIdentifiers[0]",
    "metadataStatement.attestationRootCertificates[0]",
    "metadataStatement.aaguid",
    "metadataStatement.attestationCertificateKeyIdentifiers[0]",
    "statusReports[0].batchCertificate",
    "statusReports[0].certificate",
    "rogueListHash",
]
CLASSES = [(RegistrationResponse, REGISTRATION), (AuthenticationResponse, AUTHENTICATION), (MetadataBlobPayloadEntry, METADATA_ENTRY)]


@pytest.mark.parametrize(("cls", "expected"), CLASSES)
def test_the_bytes_members_fido2_declares_are_these(cls, expected):
    assert sorted(_spelled(path) for path in _bytes_positions(cls)) == sorted(expected)


@pytest.mark.parametrize(
    ("cls", "path"), [(cls, path) for cls, _expected in CLASSES for path in _bytes_positions(cls)], ids=str
)
def test_a_number_in_each_bytes_member_fido2_declares_is_refused_by_its_name(cls, path):
    assert byte_members.number_refusal(cls, _holding(path, NUMBER)) == f"{_spelled(path)} must be text, not a number."


def _registration(**changes) -> dict:
    payload = registration_payload(Authenticator(), challenge=b"\x01" * 32)
    payload["response"].update(changes)
    return payload


def _safetynet(*, nonce, x5c) -> str:
    header = b64u(json.dumps({"alg": "RS256", "x5c": x5c}).encode())
    payload = b64u(json.dumps({"ctsProfileMatch": True, "nonce": nonce}).encode())
    statement = {"ver": "1", "response": f"{header}.{payload}.c2ln".encode()}
    return b64u(attestation_object(Authenticator().authenticator_data(), fmt="android-safetynet", att_stmt=statement))


def _client_data(challenge) -> bytes:
    return json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": "http://localhost"}).encode()


@pytest.mark.parametrize(
    ("changes", "sentence"),
    [
        ({"clientDataJSON": b64u(_client_data(NUMBER))}, "response.clientDataJSON's challenge must be text, not a number."),
        # fido2 makes bytes of a list of byte values too, and reads the client data in them.
        ({"clientDataJSON": list(_client_data(NUMBER))}, "response.clientDataJSON's challenge must be text, not a number."),
        (
            {"attestationObject": b64u(cbor.encode({"fmt": "none", "attStmt": {}, "authData": NUMBER}))},
            "response.attestationObject's authData must be a byte string, not a number.",
        ),
        (
            {"attestationObject": _safetynet(nonce=NUMBER, x5c=[])},
            "response.attestationObject's android-safetynet response's nonce must be text, not a number.",
        ),
        (
            {"attestationObject": _safetynet(nonce="bm9uY2U", x5c=["AA", NUMBER])},
            "response.attestationObject's android-safetynet response's x5c[1] must be text, not a number.",
        ),
    ],
)
def test_a_number_inside_the_bytes_fido2_parses_further_is_refused(changes, sentence):
    assert byte_members.number_refusal(RegistrationResponse, _registration(**changes)) == sentence


def test_a_number_as_the_client_datas_challenge_is_found_in_its_bytes():
    assert byte_members.client_data_number(_client_data(NUMBER))
    assert not byte_members.client_data_number(_client_data("AQID"))
    assert not byte_members.client_data_number(b"not json")


def test_a_boolean_where_bytes_belong_is_left_to_fido2():
    # bytes(True) is one byte.
    payload = _registration(clientDataJSON=True)
    payload["rawId"] = True

    assert byte_members.number_refusal(RegistrationResponse, payload) is None


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"attestationObject": _safetynet(nonce="bm9uY2U", x5c=["AA"])},
        {"attestationObject": "not base64url!", "clientDataJSON": b64u(b"[" * 100_000)},
        {"attestationObject": b64u(b"\xff\xff")},
        {"attestationObject": b64u(cbor.encode([NUMBER])), "clientDataJSON": [256, NUMBER]},
        {"attestationObject": "é", "clientDataJSON": "é"},
        {
            "attestationObject": b64u(
                attestation_object(b"", fmt="android-safetynet", att_stmt={"response": b"two.parts", "nonce": NUMBER})
            )
        },
    ],
)
def test_a_registration_response_with_no_number_for_bytes_is_left_to_fido2(changes):
    assert byte_members.number_refusal(RegistrationResponse, _registration(**changes)) is None


def test_a_response_or_member_that_is_no_object_is_left_to_fido2():
    assert byte_members.number_refusal(RegistrationResponse, NUMBER) is None
    assert byte_members.number_refusal(AuthenticationResponse, {"rawId": "AA", "response": [NUMBER]}) is None


def test_an_authentication_response_with_no_number_for_bytes_is_left_to_fido2():
    assertion = assertion_payload(Authenticator(), challenge=b"\x01" * 32, user_handle=b"user")
    assertion["clientExtensionResults"] = {"credProps": {"rk": True}, "largeBlob": {"written": True}, "appid": False}

    assert byte_members.number_refusal(AuthenticationResponse, assertion) is None


def _statements() -> list:
    verified = json.loads((FIXTURES / "snapshot" / "fido-mds3.verified.json").read_text())
    custom = json.loads((FIXTURES / "custom-metadata.json").read_text())
    return verified["entries"] + custom["entries"]


def test_every_statement_the_repository_holds_has_no_number_for_bytes():
    statements = _statements()

    assert len(statements) > 30
    assert [byte_members.number_refusal(MetadataBlobPayloadEntry, entry) for entry in statements] == [None] * len(statements)
