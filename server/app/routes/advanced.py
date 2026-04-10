"""Routes for the advanced JSON editor flows."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

from flask import jsonify, request, session
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticatorAttachment,
    AuthenticatorData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..attachments import (
    normalize_attachment,
    normalize_attachment_list,
    resolve_effective_attachments,
)
from ..attestation import (
    augment_aaguid_fields,
    extract_attestation_details,
    extract_min_pin_length,
    make_json_safe,
    perform_attestation_checks,
    summarize_authenticator_extensions,
)
from ..config import app, build_rp_entity, create_fido_server, determine_rp_id
from ..credential_artifacts import (
    delete_credential_artifact_with_status,
    load_credential_artifact,
    store_credential_artifact,
)
from ..device_logs import RegistrationEvent, record_registration_event
from ..metadata import ensure_metadata_session_id
from ..pqc import (
    PQC_ALGORITHM_ID_TO_NAME,
    describe_algorithm,
    detect_available_pqc_algorithms,
    is_pqc_algorithm,
    log_algorithm_selection,
)
from ..storage import add_public_key_material, convert_bytes_for_json, readkey
from .advanced_parts.algorithm_helpers_impl import (
    _coerce_cose_algorithm_impl,
    _derive_algorithms_from_credentials_impl,
    _extract_credential_algorithm_impl,
    _extract_requested_assertion_algorithm_impl,
    _is_custom_cose_algorithm_impl,
    _lookup_named_cose_algorithm_impl,
    _normalize_algorithm_name_key_impl,
)
from .advanced_parts.artifacts_impl import (
    api_delete_advanced_credential_artifact_impl,
    api_get_advanced_credential_artifact_impl,
    api_get_advanced_credential_artifacts_bulk_impl,
    api_put_advanced_credential_artifact_impl,
    api_put_advanced_credential_snapshot_impl,
)
from .advanced_parts.constants import (
    COSE_ALGORITHM_NAME_LOOKUP,
    COSE_ALGORITHM_NAME_MAP,
    COSE_ALGORITHM_NUMERIC_PATTERN,
    HEAVY_CREDENTIAL_KEYS,
    HEAVY_PROPERTY_KEYS,
    HEAVY_RELYING_PARTY_KEYS,
)
from .advanced_parts.authenticate_begin_impl import advanced_authenticate_begin_impl
from .advanced_parts.authenticate_complete_impl import advanced_authenticate_complete_impl
from .advanced_parts.binary_helpers_impl import (
    _decode_base64url_bytes_impl,
    _decode_base64url_impl,
    _decode_client_binary_impl,
    _encode_base64url_impl,
    _extract_assertion_credential_id_impl,
    _extract_binary_value_impl,
)
from .advanced_parts.logging_helpers_impl import (
    _log_authenticator_attestation_response_impl,
    datetime_from_timestamp_impl,
)
from .advanced_parts.parsing_helpers_impl import (
    _coerce_optional_bool_impl,
    _extract_credential_id_impl,
    _extract_flag_from_mapping_impl,
    _parse_client_supplied_credentials_impl,
    _select_first_impl,
)
from .advanced_parts.register_begin_impl import advanced_register_begin_impl
from .advanced_parts.register_complete_impl import advanced_register_complete_impl
from .advanced_parts.summary_helpers_impl import (
    _generate_storage_id_impl,
    _summarize_properties_impl,
    _summarize_relying_party_impl,
    _summarize_stored_credential_impl,
)

_COSE_ALGORITHM_NAME_MAP = COSE_ALGORITHM_NAME_MAP
_COSE_ALGORITHM_NAME_LOOKUP = COSE_ALGORITHM_NAME_LOOKUP
_COSE_ALGORITHM_NUMERIC_PATTERN = COSE_ALGORITHM_NUMERIC_PATTERN
_HEAVY_CREDENTIAL_KEYS = HEAVY_CREDENTIAL_KEYS
_HEAVY_PROPERTY_KEYS = HEAVY_PROPERTY_KEYS
_HEAVY_RELYING_PARTY_KEYS = HEAVY_RELYING_PARTY_KEYS


def _self_module() -> Any:
    return sys.modules[__name__]


def _normalize_algorithm_name_key(name: str) -> str:
    return _normalize_algorithm_name_key_impl(_self_module(), name)


def _generate_storage_id(credential_id: str) -> str:
    return _generate_storage_id_impl(_self_module(), credential_id)


def _summarize_properties(value: Any) -> Optional[Dict[str, Any]]:
    return _summarize_properties_impl(_self_module(), value)


def _summarize_relying_party(value: Any) -> Optional[Dict[str, Any]]:
    return _summarize_relying_party_impl(_self_module(), value)


def _summarize_stored_credential(stored: Mapping[str, Any], storage_id: str) -> Dict[str, Any]:
    return _summarize_stored_credential_impl(_self_module(), stored, storage_id)


def _extract_credential_id(value: Any) -> Optional[bytes]:
    return _extract_credential_id_impl(_self_module(), value)


def _extract_credential_algorithm(value: Any) -> Optional[int]:
    return _extract_credential_algorithm_impl(_self_module(), value)


def _coerce_optional_bool(value: Any) -> Optional[bool]:
    return _coerce_optional_bool_impl(_self_module(), value)


def _extract_flag_from_mapping(mapping: Mapping[str, Any], keys: Iterable[str]) -> Optional[bool]:
    return _extract_flag_from_mapping_impl(_self_module(), mapping, keys)


def _select_first(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    return _select_first_impl(_self_module(), mapping, keys)


def _decode_client_binary(value: Any) -> bytes:
    return _decode_client_binary_impl(_self_module(), value)


def _parse_client_supplied_credentials(raw_credentials: Any) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    return _parse_client_supplied_credentials_impl(_self_module(), raw_credentials)


def _derive_algorithms_from_credentials(credentials: Iterable[Any]) -> List[PublicKeyCredentialParameters]:
    return _derive_algorithms_from_credentials_impl(_self_module(), credentials)


def _lookup_named_cose_algorithm(name: str) -> Optional[int]:
    return _lookup_named_cose_algorithm_impl(_self_module(), name)


def _coerce_cose_algorithm(value: Any) -> Optional[int]:
    return _coerce_cose_algorithm_impl(_self_module(), value)


def _is_custom_cose_algorithm(alg_id: Optional[int]) -> bool:
    return _is_custom_cose_algorithm_impl(_self_module(), alg_id)


def _decode_base64url(data: str) -> bytes:
    return _decode_base64url_impl(_self_module(), data)


def _decode_base64url_bytes(value: Any) -> bytes:
    return _decode_base64url_bytes_impl(_self_module(), value)


def _extract_assertion_credential_id(response: Mapping[str, Any]) -> Optional[bytes]:
    return _extract_assertion_credential_id_impl(_self_module(), response)


def _extract_requested_assertion_algorithm(
    public_key: Mapping[str, Any],
    credential_id: Optional[bytes],
) -> Optional[int]:
    return _extract_requested_assertion_algorithm_impl(_self_module(), public_key, credential_id)


def _extract_binary_value(value: Any) -> Any:
    return _extract_binary_value_impl(_self_module(), value)


def _encode_base64url(data: bytes) -> str:
    return _encode_base64url_impl(_self_module(), data)


def _log_authenticator_attestation_response(
    attestation_format: Optional[str],
    auth_data: Any,
    attestation_statement: Any,
    raw_attestation_object: Any,
) -> None:
    return _log_authenticator_attestation_response_impl(
        _self_module(),
        attestation_format,
        auth_data,
        attestation_statement,
        raw_attestation_object,
    )


@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    return advanced_register_begin_impl(_self_module())


@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    return advanced_register_complete_impl(_self_module())


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["GET"])
def api_get_advanced_credential_artifact(storage_id: str):
    return api_get_advanced_credential_artifact_impl(_self_module(), storage_id)


@app.route("/api/advanced/credential-artifacts/bulk", methods=["POST"])
def api_get_advanced_credential_artifacts_bulk():
    return api_get_advanced_credential_artifacts_bulk_impl(_self_module())


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["PUT"])
def api_put_advanced_credential_artifact(storage_id: str):
    return api_put_advanced_credential_artifact_impl(_self_module(), storage_id)


@app.route("/api/advanced/credential-artifacts/<string:storage_id>/snapshot", methods=["PUT"])
def api_put_advanced_credential_snapshot(storage_id: str):
    return api_put_advanced_credential_snapshot_impl(_self_module(), storage_id)


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["DELETE"])
def api_delete_advanced_credential_artifact(storage_id: str):
    return api_delete_advanced_credential_artifact_impl(_self_module(), storage_id)


def datetime_from_timestamp(timestamp: float) -> str:
    return datetime_from_timestamp_impl(_self_module(), timestamp)


@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    return advanced_authenticate_begin_impl(_self_module())


@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    return advanced_authenticate_complete_impl(_self_module())
