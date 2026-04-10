"""CTAP/WebAuthn structure encoders."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from .binary_decode import _require_bytes
from .binary_extract import _restore_generic_structure
from .constants import _CTAP_PREFIX_DETAILS
from .ctap_fields import (
    _encode_allow_list,
    _encode_attestation_statement,
    _encode_ctap_user,
    _encode_credential_descriptor,
    _ensure_bool,
    _ensure_int,
    _ensure_text,
    _get_ctap_field_value,
    _require_mapping,
)


def _encode_ctap_from_decoded(
    decoded: Mapping[str, Any]
) -> Tuple[Optional[Dict[int, Any]], Optional[str]]:
    if not isinstance(decoded, Mapping):
        return None, None

    for key in (
        "makeCredentialRequest",
        "getAssertionRequest",
        "makeCredentialResponse",
        "getAssertionResponse",
    ):
        entry = decoded.get(key)
        if isinstance(entry, Mapping):
            encoded_map, kind = _encode_ctap_from_structure(entry)
            if encoded_map is not None:
                return encoded_map, key
    return None, None


def _encode_ctap_from_structure(
    structure: Mapping[str, Any]
) -> Tuple[Optional[Dict[int, Any]], Optional[str]]:
    if not isinstance(structure, Mapping):
        return None, None

    if _get_ctap_field_value(structure, "fmt", 1) is not None and _get_ctap_field_value(structure, "authData", 2) is not None:
        return _encode_make_credential_response(structure), "makeCredentialResponse"

    if _get_ctap_field_value(structure, "credential", 1) is not None or _get_ctap_field_value(structure, "signature", 3) is not None:
        return _encode_get_assertion_response(structure), "getAssertionResponse"

    if _get_ctap_field_value(structure, "rp", 2) is not None and _get_ctap_field_value(structure, "user", 3) is not None:
        return _encode_make_credential_request(structure), "makeCredentialRequest"

    if _get_ctap_field_value(structure, "rpId", 1) is not None and _get_ctap_field_value(structure, "clientDataHash", 2) is not None:
        return _encode_get_assertion_request(structure), "getAssertionRequest"

    return None, None


def _determine_ctap_prefix(
    metadata: Optional[Mapping[str, Any]],
    kind: Optional[str],
) -> Tuple[Optional[int], Optional[str]]:
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


def _encode_make_credential_request(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _require_bytes(_get_ctap_field_value(structure, "clientDataHash", 1), "clientDataHash")
    mapping[2] = _restore_generic_structure(
        _require_mapping(_get_ctap_field_value(structure, "rp", 2), "rp")
    )
    mapping[3] = _encode_ctap_user(_get_ctap_field_value(structure, "user", 3))

    params = _get_ctap_field_value(structure, "pubKeyCredParams", 4)
    if params is None:
        raise ValueError("MakeCredential request requires pubKeyCredParams.")
    mapping[4] = _restore_generic_structure(params)

    exclude_list = _get_ctap_field_value(structure, "excludeList", 5)
    if exclude_list is not None:
        mapping[5] = _encode_allow_list(exclude_list)

    extensions = _get_ctap_field_value(structure, "extensions", 6)
    if extensions is not None:
        mapping[6] = _restore_generic_structure(extensions)

    options = _get_ctap_field_value(structure, "options", 7)
    if options is not None:
        mapping[7] = _restore_generic_structure(options)

    pin_param = _get_ctap_field_value(structure, "pinUvAuthParam", 8)
    if pin_param is not None:
        mapping[8] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = _get_ctap_field_value(structure, "pinUvAuthProtocol", 9)
    if pin_protocol is not None:
        mapping[9] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    enterprise_attestation = _get_ctap_field_value(structure, "enterpriseAttestation", 10)
    if enterprise_attestation is not None:
        mapping[10] = _restore_generic_structure(enterprise_attestation)

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 11)
    if large_blob_key is not None:
        mapping[11] = _require_bytes(large_blob_key, "largeBlobKey")

    return mapping


def _encode_get_assertion_request(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _ensure_text(
        _get_ctap_field_value(structure, "rpId", 1), "rpId"
    )
    mapping[2] = _require_bytes(
        _get_ctap_field_value(structure, "clientDataHash", 2), "clientDataHash"
    )

    allow_list = _get_ctap_field_value(structure, "allowList", 3)
    if allow_list is not None:
        mapping[3] = _encode_allow_list(allow_list)

    extensions = _get_ctap_field_value(structure, "extensions", 4)
    if extensions is not None:
        mapping[4] = _restore_generic_structure(extensions)

    options = _get_ctap_field_value(structure, "options", 5)
    if options is not None:
        mapping[5] = _restore_generic_structure(options)

    pin_param = _get_ctap_field_value(structure, "pinUvAuthParam", 6)
    if pin_param is not None:
        mapping[6] = _require_bytes(pin_param, "pinUvAuthParam")

    pin_protocol = _get_ctap_field_value(structure, "pinUvAuthProtocol", 7)
    if pin_protocol is not None:
        mapping[7] = _ensure_int(pin_protocol, "pinUvAuthProtocol")

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 8)
    if large_blob_key is not None:
        mapping[8] = _require_bytes(large_blob_key, "largeBlobKey")

    return mapping


def _encode_make_credential_response(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    mapping[1] = _ensure_text(_get_ctap_field_value(structure, "fmt", 1), "fmt")
    mapping[2] = _require_bytes(_get_ctap_field_value(structure, "authData", 2), "authData")

    att_stmt = _get_ctap_field_value(structure, "attStmt", 3)
    if att_stmt is not None:
        mapping[3] = _encode_attestation_statement(att_stmt)

    ep_att = _get_ctap_field_value(structure, "epAtt", 4)
    if ep_att is not None:
        mapping[4] = _restore_generic_structure(ep_att)

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 5)
    if large_blob_key is not None:
        mapping[5] = _require_bytes(large_blob_key, "largeBlobKey")

    extensions = _get_ctap_field_value(structure, "extensions", 6)
    if extensions is not None:
        mapping[6] = _restore_generic_structure(extensions)

    return mapping


def _encode_get_assertion_response(structure: Mapping[str, Any]) -> Dict[int, Any]:
    mapping: Dict[int, Any] = {}

    credential = _get_ctap_field_value(structure, "credential", 1)
    if credential is not None:
        mapping[1] = _encode_credential_descriptor(credential)

    mapping[2] = _require_bytes(_get_ctap_field_value(structure, "authData", 2), "authData")
    mapping[3] = _require_bytes(_get_ctap_field_value(structure, "signature", 3), "signature")

    user = _get_ctap_field_value(structure, "user", 4)
    if user is not None:
        mapping[4] = _encode_ctap_user(user)

    number_of_credentials = _get_ctap_field_value(structure, "numberOfCredentials", 5)
    if number_of_credentials is not None:
        mapping[5] = _ensure_int(number_of_credentials, "numberOfCredentials")

    user_selected = _get_ctap_field_value(structure, "userSelected", 6)
    if user_selected is not None:
        mapping[6] = _ensure_bool(user_selected, "userSelected")

    large_blob_key = _get_ctap_field_value(structure, "largeBlobKey", 7)
    if large_blob_key is not None:
        mapping[7] = _require_bytes(large_blob_key, "largeBlobKey")

    extensions = _get_ctap_field_value(structure, "extensions", 8)
    if extensions is not None:
        mapping[8] = _restore_generic_structure(extensions)

    return mapping
