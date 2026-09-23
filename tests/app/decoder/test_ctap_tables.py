"""``server.app.decoder.ctap_tables`` is the one CTAP table, derived from fido2.

The request parameter numbers are the argument order ``fido2``'s ``args()``
numbers when ``Ctap2`` sends a command, the response member numbers are the
field order ``_CborDataObject`` numbers, so the codec labels a key the way the
library that talks to authenticators sends it.
"""
from __future__ import annotations

import inspect
from dataclasses import fields

from fido2.ctap2.base import AssertionResponse, AttestationResponse, Ctap2
from server.app.decoder import ctap_tables
from server.app.decoder.decode import ctap
from server.app.decoder.encode import constants


def _positional_parameters(method) -> list[str]:
    return [
        parameter.name
        for parameter in inspect.signature(method).parameters.values()
        if parameter.kind is parameter.POSITIONAL_OR_KEYWORD and parameter.name != "self"
    ]


def test_make_credential_parameters_follow_fido2_and_add_ctap_2_2():
    assert ctap_tables.MAKE_CREDENTIAL_PARAMETERS == {
        1: "clientDataHash",
        2: "rp",
        3: "user",
        4: "pubKeyCredParams",
        5: "excludeList",
        6: "extensions",
        7: "options",
        8: "pinUvAuthParam",
        9: "pinUvAuthProtocol",
        10: "enterpriseAttestation",
        11: "attestationFormatsPreference",
    }
    assert len(_positional_parameters(Ctap2.make_credential)) == 10


def test_get_assertion_has_seven_parameters_and_no_0x08():
    assert ctap_tables.GET_ASSERTION_PARAMETERS == {
        1: "rpId",
        2: "clientDataHash",
        3: "allowList",
        4: "extensions",
        5: "options",
        6: "pinUvAuthParam",
        7: "pinUvAuthProtocol",
    }
    assert len(_positional_parameters(Ctap2.get_assertion)) == 7


def test_response_members_follow_the_fido2_dataclasses():
    assert ctap_tables.MAKE_CREDENTIAL_RESPONSE == {
        1: "fmt",
        2: "authData",
        3: "attStmt",
        4: "epAtt",
        5: "largeBlobKey",
        6: "unsignedExtensionOutputs",
    }
    assert len(fields(AttestationResponse)) == 6
    assert ctap_tables.GET_ASSERTION_RESPONSE == {
        1: "credential",
        2: "authData",
        3: "signature",
        4: "user",
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "unsignedExtensionOutputs",
    }
    assert len(fields(AssertionResponse)) == 7


def test_the_decoder_and_encoder_read_the_same_tables():
    tables = {
        "makeCredentialRequest": (ctap_tables.MAKE_CREDENTIAL_PARAMETERS, ctap._MAKE_CREDENTIAL_REQUEST_LABELS),
        "getAssertionRequest": (ctap_tables.GET_ASSERTION_PARAMETERS, ctap._GET_ASSERTION_REQUEST_LABELS),
        "makeCredentialResponse": (ctap_tables.MAKE_CREDENTIAL_RESPONSE, ctap._MAKE_CREDENTIAL_RESPONSE_LABELS),
        "getAssertionResponse": (ctap_tables.GET_ASSERTION_RESPONSE, ctap._GET_ASSERTION_RESPONSE_LABELS),
    }
    for kind, (table, decoder_labels) in tables.items():
        assert constants._CTAP_FIELD_LABELS[kind] is table
        assert {key: name for key, name in decoder_labels.items() if isinstance(key, int)} == table
        assert {key for key in decoder_labels if isinstance(key, str)} == set(table.values())


def test_every_decoder_handler_is_keyed_by_a_name_in_its_table():
    for handlers, table in (
        (ctap._MAKE_CREDENTIAL_REQUEST_HANDLERS, ctap_tables.MAKE_CREDENTIAL_PARAMETERS),
        (ctap._GET_ASSERTION_REQUEST_HANDLERS, ctap_tables.GET_ASSERTION_PARAMETERS),
        (ctap._MAKE_CREDENTIAL_RESPONSE_HANDLERS, ctap_tables.MAKE_CREDENTIAL_RESPONSE),
        (ctap._GET_ASSERTION_RESPONSE_HANDLERS, ctap_tables.GET_ASSERTION_RESPONSE),
    ):
        assert set(handlers) == set(table.values())
