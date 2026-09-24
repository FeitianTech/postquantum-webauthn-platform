"""The CTAP2 tables the decoder and the encoder share.

The numbers are read off the vendored ``fido2`` library, the code this server
would use to talk to an authenticator, so the codec cannot number a field
differently from it:

* a command's parameters are numbered in the order ``Ctap2`` passes them to
  ``args()``, which numbers from 1;
* a response's members are numbered in the field order of its dataclass, which
  ``_CborDataObject`` numbers from 1;
* command bytes are ``Ctap2.CMD`` and status bytes ``CtapError.ERR``.

``fido2`` spells the names in snake_case; the codec shows the CTAP names, which
``_CTAP_NAMES`` gives. Where CTAP 2.2 defines a member the vendored ``fido2``
does not know yet, it is added below with the section that defines it. Tables
fido2 has no counterpart for -- getInfo option and certification IDs, the
uvModality bits -- are transcribed from the section cited next to each.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import fields

from fido2.ctap import CtapError
from fido2.ctap2.base import AssertionResponse, AttestationResponse, Ctap2, Info

COMMANDS: dict[int, str] = {int(command): command.name for command in Ctap2.CMD}
STATUSES: dict[int, str] = {int(status): status.name for status in CtapError.ERR}
SUCCESS: int = int(CtapError.ERR.SUCCESS)
MAKE_CREDENTIAL: int = int(Ctap2.CMD.MAKE_CREDENTIAL)
GET_ASSERTION: int = int(Ctap2.CMD.GET_ASSERTION)
GET_INFO: int = int(Ctap2.CMD.GET_INFO)

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
    # authenticatorGetInfo response members
    "versions": "versions",
    "aaguid": "aaguid",
    "max_msg_size": "maxMsgSize",
    "pin_uv_protocols": "pinUvAuthProtocols",
    "max_creds_in_list": "maxCredentialCountInList",
    "max_cred_id_length": "maxCredentialIdLength",
    "transports": "transports",
    "algorithms": "algorithms",
    "max_large_blob": "maxSerializedLargeBlobArray",
    "force_pin_change": "forcePINChange",
    "min_pin_length": "minPINLength",
    "firmware_version": "firmwareVersion",
    "max_cred_blob_length": "maxCredBlobLength",
    "max_rpids_for_min_pin": "maxRPIDsForSetMinPINLength",
    "preferred_platform_uv_attempts": "preferredPlatformUvAttempts",
    "uv_modality": "uvModality",
    "certifications": "certifications",
    "remaining_disc_creds": "remainingDiscoverableCredentials",
    "vendor_prototype_config_commands": "vendorPrototypeConfigCommands",
    "attestation_formats": "attestationFormats",
    "uv_count_since_pin": "uvCountSinceLastPinEntry",
    "long_touch_for_reset": "longTouchForReset",
    "enc_identifier": "encIdentifier",
    "transports_for_reset": "transportsForReset",
    "pin_complexity_policy": "pinComplexityPolicy",
    "pin_complexity_policy_url": "pinComplexityPolicyURL",
    "max_pin_length": "maxPINLength",
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

# CTAP 2.2 section 6.4, authenticatorGetInfo (0x04): members 0x01 (versions) to
# 0x1D (maxPINLength), in the field order of fido2's ``Info``.
GET_INFO_RESPONSE: dict[int, str] = _response_members(Info)

# CTAP 2.2 section 6.4, the option IDs "as of CTAP version FIDO_2_2": what each
# means when true, when false, and the default the table gives when it is absent.
GET_INFO_OPTIONS: dict[str, tuple[str, str, str]] = {
    "plat": (
        "platform device: attached to the client, cannot be removed and used on another client",
        "not a platform device",
        "false",
    ),
    "rk": (
        "can create discoverable credentials, so it can answer getAssertion without an allowList",
        "cannot create discoverable credentials",
        "false",
    ),
    "clientPin": (
        "accepts a PIN from the client, and a PIN has been set",
        "accepts a PIN from the client, but no PIN has been set yet",
        "not supported: the authenticator cannot accept a PIN from the client",
    ),
    "up": ("can test user presence", "cannot test user presence", "true"),
    "uv": (
        "has a built-in user verification method, and it is configured",
        "has a built-in user verification method, but it is not configured yet",
        "not supported: no built-in user verification method",
    ),
    "pinUvAuthToken": (
        "supports getPinUvAuthTokenUsingPinWithPermissions (with clientPin) and "
        "getPinUvAuthTokenUsingUvWithPermissions (with uv)",
        "does not support those getPinUvAuthToken subcommands",
        "not supported",
    ),
    "noMcGaPermissionsWithClientPin": (
        "a pinUvAuthToken obtained with a PIN lacks the mc and ga permissions",
        "a pinUvAuthToken obtained with a PIN can be used for makeCredential and getAssertion",
        "false",
    ),
    "largeBlobs": (
        "supports the authenticatorLargeBlobs command",
        "does not support the authenticatorLargeBlobs command",
        "not supported",
    ),
    "ep": (
        "enterprise attestation capable, and enterprise attestation is enabled",
        "enterprise attestation capable, but enterprise attestation is disabled",
        "not supported",
    ),
    "bioEnroll": (
        "supports authenticatorBioEnrollment, and at least one enrollment is provisioned",
        "supports authenticatorBioEnrollment, but nothing is enrolled yet",
        "not supported",
    ),
    "userVerificationMgmtPreview": (
        "FIDO_2_1_PRE prototype bio enrollment (0x40) supported, and at least one enrollment is provisioned",
        "FIDO_2_1_PRE prototype bio enrollment (0x40) supported, but nothing is enrolled yet",
        "not supported",
    ),
    "uvBioEnroll": (
        "the be permission can be requested with getPinUvAuthTokenUsingUvWithPermissions",
        "the be permission cannot be requested with getPinUvAuthTokenUsingUvWithPermissions",
        "not supported",
    ),
    "authnrCfg": (
        "supports the authenticatorConfig command",
        "does not support the authenticatorConfig command",
        "not supported",
    ),
    "uvAcfg": (
        "the acfg permission can be requested with getPinUvAuthTokenUsingUvWithPermissions",
        "the acfg permission cannot be requested with getPinUvAuthTokenUsingUvWithPermissions",
        "not supported",
    ),
    "credMgmt": (
        "supports the authenticatorCredentialManagement command",
        "does not support the authenticatorCredentialManagement command",
        "not supported",
    ),
    "perCredMgmtRO": (
        "the pcmr (read-only credential management) permission can be requested",
        "the pcmr permission cannot be requested",
        "not supported",
    ),
    "credentialMgmtPreview": (
        "supports the FIDO_2_1_PRE prototype authenticatorCredentialManagement (0x41) command",
        "does not support the prototype credential management command",
        "not supported",
    ),
    "setMinPINLength": (
        "supports the setMinPINLength subcommand",
        "does not support the setMinPINLength subcommand",
        "not supported",
    ),
    "makeCredUvNotRqd": (
        "can create non-discoverable credentials without user verification, if the platform asks",
        "requires user verification to create non-discoverable credentials",
        "false",
    ),
    "alwaysUv": (
        "supports Always Require User Verification, and it is enabled",
        "supports Always Require User Verification, but it is disabled",
        "not supported",
    ),
}

# CTAP 2.2 section 7.3.1, the certification IDs "as of CTAP version FIDO_2_2".
GET_INFO_CERTIFICATIONS: dict[str, str] = {
    "FIPS-CMVP-2": "FIPS 140-2 CMVP overall certification level (1 to 4)",
    "FIPS-CMVP-3": "FIPS 140-3 CMVP (ISO/IEC 19790:2012, 24759:2017) overall certification level (1 to 4)",
    "FIPS-CMVP-2-PHY": "FIPS 140-2 CMVP physical certification level (1 to 4)",
    "FIPS-CMVP-3-PHY": "FIPS 140-3 CMVP (ISO/IEC 19790:2012, 24759:2017) physical certification level (1 to 4)",
    "CC-EAL": "Common Criteria Evaluation Assurance Level (1 to 7)",
    "FIDO": "FIDO Alliance certification level (1 to 6: odd numbers are the numbered levels, even the plus levels)",
}

# The uvModality member (0x12) is a bitfield of the user verification methods of
# the FIDO Registry of Predefined Values (2022-05-23), section 3.1, which CTAP 2.2
# section 6.4 cites for it.
UV_MODALITY: dict[int, str] = {
    0x00000001: "presence_internal",
    0x00000002: "fingerprint_internal",
    0x00000004: "passcode_internal",
    0x00000008: "voiceprint_internal",
    0x00000010: "faceprint_internal",
    0x00000020: "location_internal",
    0x00000040: "eyeprint_internal",
    0x00000080: "pattern_internal",
    0x00000100: "handprint_internal",
    0x00000200: "none",
    0x00000400: "all",
    0x00000800: "passcode_external",
    0x00001000: "pattern_external",
}

# CTAP 2.2 section 12, "Defined Extensions": each extension identifier and the
# section that defines it.
EXTENSIONS: dict[str, str] = {
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

# CTAP 2.2 section 12.1, the credProtect values.
CRED_PROTECT_LEVELS: dict[int, str] = {
    0x01: "userVerificationOptional",
    0x02: "userVerificationOptionalWithCredentialIDList",
    0x03: "userVerificationRequired",
}

# CTAP 2.2 section 12.7, the hmac-secret getAssertion input map (section 12.8
# sends the same map in makeCredential for hmac-secret-mc).
HMAC_SECRET_INPUT: dict[int, str] = {
    0x01: "keyAgreement",
    0x02: "saltEnc",
    0x03: "saltAuth",
    0x04: "pinUvAuthProtocol",
}

# CTAP 2.2 section 12.4, the largeBlob CDDL: largeblob-makeCredential-inputs,
# largeblob-inputs (getAssertion) and the unsigned outputs, largeblob-outputs
# with the makeCredential {"supported": true}.
LARGE_BLOB_MAKE_CREDENTIAL_INPUT: tuple[str, ...] = ("support",)
LARGE_BLOB_GET_ASSERTION_INPUT: tuple[str, ...] = ("read", "write", "originalSize")
LARGE_BLOB_OUTPUTS: tuple[str, ...] = ("supported", "written", "blob", "originalSize")

# The client extension outputs CTAP 2.2 section 12 defines (the "Client extension
# output" of each extension), by the section that defines them.
CLIENT_EXTENSION_OUTPUTS: dict[str, str] = {
    "credBlob": "12.2",
    "getCredBlob": "12.2",
    "hmacCreateSecret": "12.7",
    "hmacGetSecret": "12.7",
}
