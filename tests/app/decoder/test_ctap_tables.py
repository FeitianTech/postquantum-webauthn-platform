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
        # Numbers only: a text key named like a member is not that member.
        assert decoder_labels == table
        assert all(isinstance(key, int) for key in decoder_labels)


def test_every_decoder_handler_is_keyed_by_a_name_in_its_table():
    for handlers, table in (
        (ctap._MAKE_CREDENTIAL_REQUEST_HANDLERS, ctap_tables.MAKE_CREDENTIAL_PARAMETERS),
        (ctap._GET_ASSERTION_REQUEST_HANDLERS, ctap_tables.GET_ASSERTION_PARAMETERS),
        (ctap._MAKE_CREDENTIAL_RESPONSE_HANDLERS, ctap_tables.MAKE_CREDENTIAL_RESPONSE),
        (ctap._GET_ASSERTION_RESPONSE_HANDLERS, ctap_tables.GET_ASSERTION_RESPONSE),
    ):
        assert set(handlers) == set(table.values())


def test_get_info_members_are_ctap_2_2_section_6_4():
    from fido2.ctap2.base import Info

    # CTAP 2.2 section 6.4, the authenticatorGetInfo response structure.
    assert ctap_tables.GET_INFO == 0x04
    assert ctap_tables.GET_INFO_RESPONSE == {
        0x01: "versions",
        0x02: "extensions",
        0x03: "aaguid",
        0x04: "options",
        0x05: "maxMsgSize",
        0x06: "pinUvAuthProtocols",
        0x07: "maxCredentialCountInList",
        0x08: "maxCredentialIdLength",
        0x09: "transports",
        0x0A: "algorithms",
        0x0B: "maxSerializedLargeBlobArray",
        0x0C: "forcePINChange",
        0x0D: "minPINLength",
        0x0E: "firmwareVersion",
        0x0F: "maxCredBlobLength",
        0x10: "maxRPIDsForSetMinPINLength",
        0x11: "preferredPlatformUvAttempts",
        0x12: "uvModality",
        0x13: "certifications",
        0x14: "remainingDiscoverableCredentials",
        0x15: "vendorPrototypeConfigCommands",
        0x16: "attestationFormats",
        0x17: "uvCountSinceLastPinEntry",
        0x18: "longTouchForReset",
        0x19: "encIdentifier",
        0x1A: "transportsForReset",
        0x1B: "pinComplexityPolicy",
        0x1C: "pinComplexityPolicyURL",
        0x1D: "maxPINLength",
    }
    assert len(fields(Info)) == 29


def test_get_info_option_ids_are_the_ctap_2_2_table_with_its_defaults():
    # CTAP 2.2 section 6.4, the option ID table "as of CTAP version FIDO_2_2".
    defaults = {option: entry[2] for option, entry in ctap_tables.GET_INFO_OPTIONS.items()}
    assert defaults == {
        "plat": "false",
        "rk": "false",
        "clientPin": "not supported: the authenticator cannot accept a PIN from the client",
        "up": "true",
        "uv": "not supported: no built-in user verification method",
        "pinUvAuthToken": "not supported",
        "noMcGaPermissionsWithClientPin": "false",
        "largeBlobs": "not supported",
        "ep": "not supported",
        "bioEnroll": "not supported",
        "userVerificationMgmtPreview": "not supported",
        "uvBioEnroll": "not supported",
        "authnrCfg": "not supported",
        "uvAcfg": "not supported",
        "credMgmt": "not supported",
        "perCredMgmtRO": "not supported",
        "credentialMgmtPreview": "not supported",
        "setMinPINLength": "not supported",
        "makeCredUvNotRqd": "false",
        "alwaysUv": "not supported",
    }


def test_certification_ids_and_uv_modality_bits():
    # CTAP 2.2 section 7.3.1.
    assert set(ctap_tables.GET_INFO_CERTIFICATIONS) == {
        "FIPS-CMVP-2", "FIPS-CMVP-3", "FIPS-CMVP-2-PHY", "FIPS-CMVP-3-PHY", "CC-EAL", "FIDO",
    }
    # FIDO Registry of Predefined Values (2022-05-23), section 3.1.
    assert ctap_tables.UV_MODALITY == {
        0x001: "presence_internal",
        0x002: "fingerprint_internal",
        0x004: "passcode_internal",
        0x008: "voiceprint_internal",
        0x010: "faceprint_internal",
        0x020: "location_internal",
        0x040: "eyeprint_internal",
        0x080: "pattern_internal",
        0x100: "handprint_internal",
        0x200: "none",
        0x400: "all",
        0x800: "passcode_external",
        0x1000: "pattern_external",
    }


def test_the_extension_table_is_ctap_2_2_section_12_and_agrees_with_fido2():
    from fido2.ctap2.extensions import (
        CredBlobExtension,
        CredProtectExtension,
        HmacSecretExtension,
        LargeBlobExtension,
        MinPinLengthExtension,
        ThirdPartyPaymentExtension,
    )

    assert ctap_tables.EXTENSIONS == {
        "credProtect": "12.1",
        "credBlob": "12.2",
        "largeBlobKey": "12.3",
        "largeBlob": "12.4",
        "minPinLength": "12.5",
        "pinComplexityPolicy": "12.6",
        "hmac-secret": "12.7",
        "hmac-secret-mc": "12.8",
        "thirdPartyPayment": "12.9",
    }
    for name in (
        CredProtectExtension.NAME,
        CredBlobExtension.NAME,
        LargeBlobExtension.NAME,
        MinPinLengthExtension.NAME,
        HmacSecretExtension.NAME,
        HmacSecretExtension.MC_NAME,
        ThirdPartyPaymentExtension.NAME,
    ):
        assert name in ctap_tables.EXTENSIONS
    # Section 12.1's table, in the order fido2 lists the policies.
    assert ctap_tables.CRED_PROTECT_LEVELS == {
        number: policy.value for number, policy in enumerate(CredProtectExtension.POLICY, 1)
    }
    assert ctap_tables.HMAC_SECRET_INPUT == {1: "keyAgreement", 2: "saltEnc", 3: "saltAuth", 4: "pinUvAuthProtocol"}
    assert ctap_tables.CLIENT_EXTENSION_OUTPUTS == {
        "credBlob": "12.2",
        "getCredBlob": "12.2",
        "hmacCreateSecret": "12.7",
        "hmacGetSecret": "12.7",
    }
