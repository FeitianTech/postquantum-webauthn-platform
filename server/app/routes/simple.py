"""Routes for the basic registration and authentication flows."""
from __future__ import annotations

import base64
import hashlib
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from flask import abort, jsonify, request, session

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, PublicKeyCredentialUserEntity
from ..attachments import normalize_attachment
from ..attestation import (
    augment_aaguid_fields,
    coerce_aaguid_hex,
    extract_attestation_details,
    extract_min_pin_length,
    make_json_safe,
    perform_attestation_checks,
)
from ..config import app, create_fido_server, determine_rp_id
from ..device_logs import RegistrationEvent, record_registration_event
from ..metadata import ensure_metadata_session_id
from ..storage import (
    add_public_key_material,
    convert_bytes_for_json,
    delkey,
    iter_credentials,
    list_credentials as storage_list_credentials,
    readkey,
    savekey,
)
from .simple_parts.authenticate_impl import authenticate_begin_impl, authenticate_complete_impl
from .simple_parts.binary_helpers_impl import (
    _add_base64_padding_impl,
    _decode_base64url_bytes_impl,
    _decode_binary_value_impl,
    _extract_assertion_credential_id_impl,
    _select_first_impl,
)
from .simple_parts.credential_parsing_impl import (
    _parse_client_credentials_impl,
    _serialize_credential_for_session_impl,
)
from .simple_parts.credentials_route_impl import list_credentials_impl
from .simple_parts.register_begin_impl import register_begin_impl
from .simple_parts.register_complete_impl import register_complete_impl

_SIMPLE_ALLOWED_ALGORITHMS: Tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)


__all__ = [
    "_SIMPLE_ALLOWED_ALGORITHMS",
    "_add_base64_padding",
    "_decode_base64url_bytes",
    "_extract_assertion_credential_id",
    "_decode_binary_value",
    "_select_first",
    "_serialize_credential_for_session",
    "_parse_client_credentials",
    "register_begin",
    "register_complete",
    "authenticate_begin",
    "authenticate_complete",
    "list_credentials",
]


def _self_module() -> Any:
    return sys.modules[__name__]


def _add_base64_padding(value: str) -> str:
    return _add_base64_padding_impl(_self_module(), value)


def _decode_base64url_bytes(value: Any) -> bytes:
    return _decode_base64url_bytes_impl(_self_module(), value)


def _extract_assertion_credential_id(response: Mapping[str, Any]) -> Optional[bytes]:
    return _extract_assertion_credential_id_impl(_self_module(), response)


def _decode_binary_value(value: Any) -> bytes:
    return _decode_binary_value_impl(_self_module(), value)


def _select_first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    return _select_first_impl(_self_module(), mapping, keys)


def _serialize_credential_for_session(entry: Mapping[str, Any]) -> Dict[str, Any]:
    return _serialize_credential_for_session_impl(_self_module(), entry)


def _parse_client_credentials(raw_credentials: Any) -> Tuple[List[AttestedCredentialData], List[Dict[str, Any]]]:
    return _parse_client_credentials_impl(_self_module(), raw_credentials)


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    return register_begin_impl(_self_module())


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    return register_complete_impl(_self_module())


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    return authenticate_begin_impl(_self_module())


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    return authenticate_complete_impl(_self_module())


@app.route("/api/credentials", methods=["GET", "DELETE"])
def list_credentials():
    return list_credentials_impl(_self_module())
