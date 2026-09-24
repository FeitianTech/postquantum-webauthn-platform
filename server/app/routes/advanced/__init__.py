"""Routes for the advanced JSON editor flows.

The implementation lives in this package's submodules; this module is the HTTP
face of it -- the Flask rules, plus re-exports of the pieces callers use. Each
submodule resolves its own names through its own imports, so a name here is the
same object the submodule defines -- patching one of these re-exports changes what
callers of *this package* see, not what the submodules call.
"""
from __future__ import annotations

from flask import Blueprint

from .. import binary_helpers
from . import (
    algorithms,
    artifacts,
    authentication,
    binary,
    constants,
    parsing,
    registration,
    summary,
    tracing,
)

# COSE name tables and the heavy-field key sets.
_COSE_ALGORITHM_NAME_MAP = constants.COSE_ALGORITHM_NAME_MAP
_COSE_ALGORITHM_NAME_LOOKUP = constants.COSE_ALGORITHM_NAME_LOOKUP
_COSE_ALGORITHM_NUMERIC_PATTERN = constants.COSE_ALGORITHM_NUMERIC_PATTERN
_HEAVY_CREDENTIAL_KEYS = constants.HEAVY_CREDENTIAL_KEYS
_HEAVY_PROPERTY_KEYS = constants.HEAVY_PROPERTY_KEYS
_HEAVY_RELYING_PARTY_KEYS = constants.HEAVY_RELYING_PARTY_KEYS

# COSE algorithm coercion and discovery.
_coerce_cose_algorithm = algorithms._coerce_cose_algorithm
_derive_algorithms_from_credentials = algorithms._derive_algorithms_from_credentials
_extract_credential_algorithm = algorithms._extract_credential_algorithm
_lookup_named_cose_algorithm = algorithms._lookup_named_cose_algorithm
_normalize_algorithm_name_key = algorithms._normalize_algorithm_name_key

# base64url and binary extraction.
_decode_base64url = binary._decode_base64url
_decode_base64url_bytes = binary_helpers.decode_base64url_bytes
_decode_client_binary = binary._decode_client_binary
_encode_base64url = binary._encode_base64url
_extract_assertion_credential_id = binary_helpers.extract_assertion_credential_id
_extract_binary_value = binary._extract_binary_value

# Client-supplied credential parsing.
_coerce_optional_bool = parsing._coerce_optional_bool
_extract_flag_from_mapping = parsing._extract_flag_from_mapping
_parse_client_supplied_credentials = parsing._parse_client_supplied_credentials
_select_first = parsing._select_first

# Stored-credential summaries.
_generate_storage_id = summary._generate_storage_id
_summarize_properties = summary._summarize_properties
_summarize_relying_party = summary._summarize_relying_party
_summarize_stored_credential = summary._summarize_stored_credential

# Attestation-response logging.
_log_authenticator_attestation_response = (
    tracing._log_authenticator_attestation_response
)
datetime_from_timestamp = tracing.datetime_from_timestamp


# The HTTP rules, registered on the app by server.app.app.
bp = Blueprint("advanced", __name__)


@bp.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    return registration.advanced_register_begin()


@bp.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    return registration.advanced_register_complete()


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["GET"])
def api_get_advanced_credential_artifact(storage_id: str):
    return artifacts.api_get_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/credential-artifacts/bulk", methods=["POST"])
def api_get_advanced_credential_artifacts_bulk():
    return artifacts.api_get_advanced_credential_artifacts_bulk()


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["PUT"])
def api_put_advanced_credential_artifact(storage_id: str):
    return artifacts.api_put_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>/snapshot", methods=["PUT"])
def api_put_advanced_credential_snapshot(storage_id: str):
    return artifacts.api_put_advanced_credential_snapshot(storage_id)


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["DELETE"])
def api_delete_advanced_credential_artifact(storage_id: str):
    return artifacts.api_delete_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    return authentication.advanced_authenticate_begin()


@bp.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    return authentication.advanced_authenticate_complete()
