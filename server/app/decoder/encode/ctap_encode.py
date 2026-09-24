"""CTAP/WebAuthn structure encoders."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import encoding
from .binary_decode import _require_bytes
from .binary_extract import _restore_generic_structure
from .constants import _CTAP_PREFIX_DETAILS
from .ctap_fields import (
    _encode_allow_list,
    _encode_attestation_statement,
    _encode_credential_descriptor,
    _encode_ctap_user,
    _ensure_bool,
    _ensure_int,
    _ensure_text,
    _get_ctap_member,
    _reject_misnamed_request_fields,
    _reject_unknown_members,
    _require_mapping,
)

_MAKE_CREDENTIAL_REQUEST = "makeCredentialRequest"
_GET_ASSERTION_REQUEST = "getAssertionRequest"
_MAKE_CREDENTIAL_RESPONSE = "makeCredentialResponse"
_GET_ASSERTION_RESPONSE = "getAssertionResponse"


def _encode_ctap_from_decoded(
    decoded: Mapping[str, Any]
) -> tuple[dict[int, Any] | None, str | None]:
    if not isinstance(decoded, Mapping):
        return None, None

    # The decoder has already said which CTAP map this is; classifying the
    # fields again could read a request as a response.
    encoders = {
        _MAKE_CREDENTIAL_REQUEST: _encode_make_credential_request,
        _GET_ASSERTION_REQUEST: _encode_get_assertion_request,
        _MAKE_CREDENTIAL_RESPONSE: _encode_make_credential_response,
        _GET_ASSERTION_RESPONSE: _encode_get_assertion_response,
    }
    others = [key for key in decoded if key not in encoders]
    if others:
        raise ValueError(
            f"ctapDecoded.{others[0]} is not a CTAP message the encoder builds; it builds "
            f"{', '.join(encoders)}."
        )
    if len(decoded) > 1:
        raise ValueError(f"ctapDecoded holds {len(decoded)} messages ({', '.join(decoded)}); give it one.")
    for key, encoder in encoders.items():
        entry = decoded.get(key)
        if isinstance(entry, Mapping):
            return encoder(entry), key
        if entry is not None:
            raise ValueError(f"ctapDecoded.{key} must be an object for encoding.")
    return None, None


def _encode_ctap_from_structure(
    structure: Mapping[str, Any]
) -> tuple[dict[int, Any] | None, str | None]:
    if not isinstance(structure, Mapping):
        return None, None

    def present(kind: str, number: int) -> bool:
        return _get_ctap_member(structure, kind, number) is not None

    if present(_MAKE_CREDENTIAL_RESPONSE, 1) and present(_MAKE_CREDENTIAL_RESPONSE, 2):
        return _encode_make_credential_response(structure), _MAKE_CREDENTIAL_RESPONSE

    if present(_GET_ASSERTION_RESPONSE, 1) or present(_GET_ASSERTION_RESPONSE, 3):
        return _encode_get_assertion_response(structure), _GET_ASSERTION_RESPONSE

    if present(_MAKE_CREDENTIAL_REQUEST, 2) and present(_MAKE_CREDENTIAL_REQUEST, 3):
        return _encode_make_credential_request(structure), _MAKE_CREDENTIAL_REQUEST

    if present(_GET_ASSERTION_REQUEST, 1) and present(_GET_ASSERTION_REQUEST, 2):
        return _encode_get_assertion_request(structure), _GET_ASSERTION_REQUEST

    return None, None


def _determine_ctap_prefix(
    metadata: Mapping[str, Any] | None,
    kind: str | None,
) -> tuple[int | None, str | None]:
    if isinstance(metadata, Mapping):
        code = metadata.get("code")
        if not isinstance(code, int):
            code_hex = metadata.get("codeHex")
            if isinstance(code_hex, str):
                try:
                    code = int(code_hex, 16)
                except ValueError:
                    code = None
        kind_hint = metadata.get("kind") if isinstance(metadata.get("kind"), str) else None
        if isinstance(code, int) and 0 <= code <= 0xFF:
            return code, kind_hint

    if kind in _CTAP_PREFIX_DETAILS:
        return _CTAP_PREFIX_DETAILS[kind]

    return None, None


def _encode_make_credential_request(structure: Mapping[str, Any]) -> dict[int, Any]:
    _reject_misnamed_request_fields(structure, _MAKE_CREDENTIAL_REQUEST)
    _reject_unknown_members(structure, _MAKE_CREDENTIAL_REQUEST)

    def member(number: int) -> Any:
        return _get_ctap_member(structure, _MAKE_CREDENTIAL_REQUEST, number)

    mapping: dict[int, Any] = {}

    mapping[1] = _require_bytes(member(1), "clientDataHash")
    mapping[2] = _restore_generic_structure(_require_mapping(member(2), "rp"))
    mapping[3] = _encode_ctap_user(member(3))

    params = member(4)
    if params is None:
        raise ValueError("MakeCredential request requires pubKeyCredParams.")
    mapping[4] = _restore_generic_structure(params)

    exclude_list = member(5)
    if exclude_list is not None:
        mapping[5] = _encode_allow_list(exclude_list)

    extensions = member(6)
    if extensions is not None:
        mapping[6] = _restore_generic_structure(extensions)

    options = member(7)
    if options is not None:
        mapping[7] = _restore_generic_structure(options)

    pin_param = member(8)
    if pin_param is not None:
        mapping[8] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = member(9)
    if pin_protocol is not None:
        mapping[9] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    enterprise_attestation = member(10)
    if enterprise_attestation is not None:
        mapping[10] = _restore_generic_structure(enterprise_attestation)

    formats = member(11)
    if formats is not None:
        if not isinstance(formats, list):
            raise ValueError("attestationFormatsPreference must be an array of attestation format strings.")
        mapping[11] = [_ensure_text(entry, "attestationFormatsPreference entry") for entry in formats]

    return mapping


def _encode_get_assertion_request(structure: Mapping[str, Any]) -> dict[int, Any]:
    _reject_misnamed_request_fields(structure, _GET_ASSERTION_REQUEST)
    _reject_unknown_members(structure, _GET_ASSERTION_REQUEST)

    def member(number: int) -> Any:
        return _get_ctap_member(structure, _GET_ASSERTION_REQUEST, number)

    mapping: dict[int, Any] = {}

    mapping[1] = _ensure_text(member(1), "rpId")
    mapping[2] = _require_bytes(member(2), "clientDataHash")

    allow_list = member(3)
    if allow_list is not None:
        mapping[3] = _encode_allow_list(allow_list)

    extensions = member(4)
    if extensions is not None:
        mapping[4] = _restore_generic_structure(extensions)

    options = member(5)
    if options is not None:
        mapping[5] = _restore_generic_structure(options)

    pin_param = member(6)
    if pin_param is not None:
        mapping[6] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = member(7)
    if pin_protocol is not None:
        mapping[7] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    return mapping


def _encode_make_credential_response(structure: Mapping[str, Any]) -> dict[int, Any]:
    _reject_unknown_members(structure, _MAKE_CREDENTIAL_RESPONSE)

    def member(number: int) -> Any:
        return _get_ctap_member(structure, _MAKE_CREDENTIAL_RESPONSE, number)

    mapping: dict[int, Any] = {}

    mapping[1] = _ensure_text(member(1), "fmt")
    mapping[2] = _auth_data_bytes(member(2))

    att_stmt = member(3)
    if att_stmt is not None:
        mapping[3] = _encode_attestation_statement(att_stmt)

    ep_att = member(4)
    if ep_att is not None:
        mapping[4] = _restore_generic_structure(ep_att)

    large_blob_key = member(5)
    if large_blob_key is not None:
        mapping[5] = _require_bytes(large_blob_key, "largeBlobKey")

    unsigned_extension_outputs = member(6)
    if unsigned_extension_outputs is not None:
        mapping[6] = _restore_generic_structure(unsigned_extension_outputs)

    return mapping


def _encode_get_assertion_response(structure: Mapping[str, Any]) -> dict[int, Any]:
    _reject_unknown_members(structure, _GET_ASSERTION_RESPONSE)

    def member(number: int) -> Any:
        return _get_ctap_member(structure, _GET_ASSERTION_RESPONSE, number)

    mapping: dict[int, Any] = {}

    credential = member(1)
    if credential is not None:
        mapping[1] = _encode_credential_descriptor(credential)

    mapping[2] = _auth_data_bytes(member(2))
    mapping[3] = _require_bytes(member(3), "signature")

    user = member(4)
    if user is not None:
        mapping[4] = _encode_ctap_user(user)

    number_of_credentials = member(5)
    if number_of_credentials is not None:
        mapping[5] = _ensure_int(number_of_credentials, "numberOfCredentials")

    user_selected = member(6)
    if user_selected is not None:
        mapping[6] = _ensure_bool(user_selected, "userSelected")

    large_blob_key = member(7)
    if large_blob_key is not None:
        mapping[7] = _require_bytes(large_blob_key, "largeBlobKey")

    unsigned_extension_outputs = member(8)
    if unsigned_extension_outputs is not None:
        mapping[8] = _restore_generic_structure(unsigned_extension_outputs)

    return mapping


def _auth_data_bytes(value: Any) -> bytes:
    """authData, with the bytes the decoder showed after it put back: nothing dropped."""

    data = _require_bytes(value, "authData")
    trailing = value.get("trailingBytesHex") if isinstance(value, Mapping) else None
    if trailing is None:
        return data
    tail = encoding.try_decode_hex(trailing) if isinstance(trailing, str) else None
    if tail is None:
        raise ValueError("authData trailingBytesHex must be hex.")
    return data + tail
