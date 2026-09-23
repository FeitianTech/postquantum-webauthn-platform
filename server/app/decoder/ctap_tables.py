"""The CTAP2 tables the decoder and the encoder share.

The numbers are read off the vendored ``fido2`` library, the code this server
would use to talk to an authenticator, so the codec cannot number a field
differently from it:

* a command's parameters are numbered in the order ``Ctap2`` passes them to
  ``args()``, which numbers from 1;
* a response's members are numbered in the field order of its dataclass, which
  ``_CborDataObject`` numbers from 1.

``fido2`` spells the names in snake_case; the codec shows the CTAP names, which
``_CTAP_NAMES`` gives. Where CTAP 2.2 defines a member the vendored ``fido2``
does not know yet, it is added below with the section that defines it.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import fields

from fido2.ctap2.base import AssertionResponse, AttestationResponse, Ctap2

_CTAP_NAMES: dict[str, str] = {
    # authenticatorMakeCredential / authenticatorGetAssertion parameters
    "client_data_hash": "clientDataHash",
    "rp": "rp",
    "rp_id": "rpId",
    "user": "user",
    "key_params": "pubKeyCredParams",
    "exclude_list": "excludeList",
    "allow_list": "allowList",
    "extensions": "extensions",
    "options": "options",
    "pin_uv_param": "pinUvAuthParam",
    "pin_uv_protocol": "pinUvAuthProtocol",
    "enterprise_attestation": "enterpriseAttestation",
    # authenticatorMakeCredential / authenticatorGetAssertion response members
    "fmt": "fmt",
    "auth_data": "authData",
    "att_stmt": "attStmt",
    "ep_att": "epAtt",
    "large_blob_key": "largeBlobKey",
    "unsigned_extension_outputs": "unsignedExtensionOutputs",
    "credential": "credential",
    "signature": "signature",
    "number_of_credentials": "numberOfCredentials",
    "user_selected": "userSelected",
}


def _command_parameters(command: Callable[..., object]) -> dict[int, str]:
    names = [
        parameter.name
        for parameter in inspect.signature(command).parameters.values()
        if parameter.kind is parameter.POSITIONAL_OR_KEYWORD and parameter.name != "self"
    ]
    return {number: _CTAP_NAMES[name] for number, name in enumerate(names, 1)}


def _response_members(response: type) -> dict[int, str]:
    return {number: _CTAP_NAMES[member.name] for number, member in enumerate(fields(response), 1)}


MAKE_CREDENTIAL_PARAMETERS: dict[int, str] = _command_parameters(Ctap2.make_credential)
# CTAP 2.2 section 6.1, authenticatorMakeCredential (0x01): parameter 0x0B is
# attestationFormatsPreference, an array of attestation format identifiers.
MAKE_CREDENTIAL_PARAMETERS[0x0B] = "attestationFormatsPreference"

# CTAP 2.2 section 6.2, authenticatorGetAssertion (0x02), defines 0x01-0x07.
GET_ASSERTION_PARAMETERS: dict[int, str] = _command_parameters(Ctap2.get_assertion)

MAKE_CREDENTIAL_RESPONSE: dict[int, str] = _response_members(AttestationResponse)

GET_ASSERTION_RESPONSE: dict[int, str] = _response_members(AssertionResponse)
# CTAP 2.2 section 6.2, authenticatorGetAssertion response: member 0x08 is
# unsignedExtensionOutputs, as 0x06 is in the makeCredential response.
GET_ASSERTION_RESPONSE[0x08] = "unsignedExtensionOutputs"
