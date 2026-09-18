"""Routes for the advanced JSON editor flows.

The implementation lives in :mod:`server.app.routes.advanced_parts`; this module is
the HTTP face of it -- the Flask rules, plus re-exports of the pieces callers use.
Each fragment resolves its own names through its own imports, so a name here is the
same object the fragment defines -- patching one of these re-exports changes what
callers of *this module* see, not what the fragments call.
"""
from __future__ import annotations

from ..config import app
from .advanced_parts import (
    algorithm_helpers_impl,
    artifacts_impl,
    authenticate_begin_impl,
    authenticate_complete_impl,
    binary_helpers_impl,
    constants,
    logging_helpers_impl,
    parsing_helpers_impl,
    register_begin_impl,
    register_complete_impl,
    summary_helpers_impl,
)

# COSE name tables and the heavy-field key sets.
_COSE_ALGORITHM_NAME_MAP = constants.COSE_ALGORITHM_NAME_MAP
_COSE_ALGORITHM_NAME_LOOKUP = constants.COSE_ALGORITHM_NAME_LOOKUP
_COSE_ALGORITHM_NUMERIC_PATTERN = constants.COSE_ALGORITHM_NUMERIC_PATTERN
_HEAVY_CREDENTIAL_KEYS = constants.HEAVY_CREDENTIAL_KEYS
_HEAVY_PROPERTY_KEYS = constants.HEAVY_PROPERTY_KEYS
_HEAVY_RELYING_PARTY_KEYS = constants.HEAVY_RELYING_PARTY_KEYS

# COSE algorithm coercion and discovery.
_coerce_cose_algorithm = algorithm_helpers_impl._coerce_cose_algorithm_impl
_derive_algorithms_from_credentials = algorithm_helpers_impl._derive_algorithms_from_credentials_impl
_extract_credential_algorithm = algorithm_helpers_impl._extract_credential_algorithm_impl
_extract_requested_assertion_algorithm = (
    algorithm_helpers_impl._extract_requested_assertion_algorithm_impl
)
_is_custom_cose_algorithm = algorithm_helpers_impl._is_custom_cose_algorithm_impl
_lookup_named_cose_algorithm = algorithm_helpers_impl._lookup_named_cose_algorithm_impl
_normalize_algorithm_name_key = algorithm_helpers_impl._normalize_algorithm_name_key_impl

# base64url and binary extraction.
_decode_base64url = binary_helpers_impl._decode_base64url_impl
_decode_base64url_bytes = binary_helpers_impl._decode_base64url_bytes_impl
_decode_client_binary = binary_helpers_impl._decode_client_binary_impl
_encode_base64url = binary_helpers_impl._encode_base64url_impl
_extract_assertion_credential_id = binary_helpers_impl._extract_assertion_credential_id_impl
_extract_binary_value = binary_helpers_impl._extract_binary_value_impl

# Client-supplied credential parsing.
_coerce_optional_bool = parsing_helpers_impl._coerce_optional_bool_impl
_extract_credential_id = parsing_helpers_impl._extract_credential_id_impl
_extract_flag_from_mapping = parsing_helpers_impl._extract_flag_from_mapping_impl
_parse_client_supplied_credentials = parsing_helpers_impl._parse_client_supplied_credentials_impl
_select_first = parsing_helpers_impl._select_first_impl

# Stored-credential summaries.
_generate_storage_id = summary_helpers_impl._generate_storage_id_impl
_summarize_properties = summary_helpers_impl._summarize_properties_impl
_summarize_relying_party = summary_helpers_impl._summarize_relying_party_impl
_summarize_stored_credential = summary_helpers_impl._summarize_stored_credential_impl

# Attestation-response logging.
_log_authenticator_attestation_response = (
    logging_helpers_impl._log_authenticator_attestation_response_impl
)
datetime_from_timestamp = logging_helpers_impl.datetime_from_timestamp_impl


@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    return register_begin_impl.advanced_register_begin_impl()


@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    return register_complete_impl.advanced_register_complete_impl()


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["GET"])
def api_get_advanced_credential_artifact(storage_id: str):
    return artifacts_impl.api_get_advanced_credential_artifact_impl(storage_id)


@app.route("/api/advanced/credential-artifacts/bulk", methods=["POST"])
def api_get_advanced_credential_artifacts_bulk():
    return artifacts_impl.api_get_advanced_credential_artifacts_bulk_impl()


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["PUT"])
def api_put_advanced_credential_artifact(storage_id: str):
    return artifacts_impl.api_put_advanced_credential_artifact_impl(storage_id)


@app.route("/api/advanced/credential-artifacts/<string:storage_id>/snapshot", methods=["PUT"])
def api_put_advanced_credential_snapshot(storage_id: str):
    return artifacts_impl.api_put_advanced_credential_snapshot_impl(storage_id)


@app.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["DELETE"])
def api_delete_advanced_credential_artifact(storage_id: str):
    return artifacts_impl.api_delete_advanced_credential_artifact_impl(storage_id)


@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    return authenticate_begin_impl.advanced_authenticate_begin_impl()


@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    return authenticate_complete_impl.advanced_authenticate_complete_impl()
