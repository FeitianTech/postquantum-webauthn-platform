"""Utilities for decoding WebAuthn-related payloads for the demo decoder.

The implementation lives in this package's submodules; this module is the public
face of it and re-exports the pieces callers use. Each fragment
resolves its own names through its own imports, so a name here is the same
object the fragment defines -- patching one of these re-exports changes what
callers of *this module* see, not what the fragments call.
"""
from __future__ import annotations

from ...webauthn import attestation
from . import (
    binary,
    cbor_parser,
    certificates,
    ctap,
    keys,
    pipeline,
    response,
    summary,
)

__all__ = ["decode_payload_text"]

# The decoder entry point.
decode_payload_text = pipeline.decode_payload_text

# Encoding helpers shared with the attestation package.
colon_hex = attestation.colon_hex
encode_base64url = attestation.encode_base64url
format_hex_bytes_lines = attestation.format_hex_bytes_lines
format_hex_string_lines = attestation.format_hex_string_lines
make_json_safe = attestation.make_json_safe
serialize_attestation_certificate = attestation.serialize_attestation_certificate
summarize_authenticator_extensions = attestation.summarize_authenticator_extensions

# Mapping-key coercion and JSON-safety helpers.
_MISSING = keys.MISSING
_coerce_cbor_bytes = keys.coerce_cbor_bytes
_get_mapping_entry = keys.get_mapping_entry
_hex_json_safe = keys.hex_json_safe
_key_identity = keys.key_identity
_make_hex_only = keys.make_hex_only
_stringify_mapping_keys = keys.stringify_mapping_keys

# Binary, hex and COSE key extraction.
_convert_cose_key_for_display = binary._convert_cose_key_for_display
_decode_base64_field = binary._decode_base64_field
_extract_authenticator_bytes = binary._extract_authenticator_bytes
_extract_authenticator_bytes_from_attestation = (
    binary._extract_authenticator_bytes_from_attestation
)
_extract_bytes_from_binary = binary._extract_bytes_from_binary
_extract_hex_from_binary = binary._extract_hex_from_binary
_resolve_cose_algorithm = binary._resolve_cose_algorithm

# The one CBOR parser: strict, lenient only when asked.
CborDiagnostic = cbor_parser.CborDiagnostic
_CborDecodingError = cbor_parser._CborDecodingError
_decode_cbor_structure = cbor_parser._decode_cbor_structure
_float_summary = cbor_parser._float_summary
_parse_cbor_item = cbor_parser._parse_cbor_item
_read_cbor_length = cbor_parser._read_cbor_length
_structure_to_value = cbor_parser._structure_to_value
decode_item = cbor_parser.decode_item

# Certificate extension serialisation.
_DEVICE_IDENTIFIER_NAMES = certificates._DEVICE_IDENTIFIER_NAMES
_build_certificate_extensions_lines = certificates._build_certificate_extensions_lines
_format_certificate_extension_header = certificates._format_certificate_extension_header
_format_certificate_extension_value = certificates._format_certificate_extension_value
_format_device_identifier_line = certificates._format_device_identifier_line

# Certificate summary line builders.
_build_fingerprint_lines = certificates._build_fingerprint_lines
_build_signature_lines = certificates._build_signature_lines
_build_subject_key_identifier_lines = certificates._build_subject_key_identifier_lines
_build_subject_public_key_info_lines = certificates._build_subject_public_key_info_lines
_format_certificate_time = certificates._format_certificate_time
_format_public_key_point_lines = certificates._format_public_key_point_lines

# Credential payload conversion leaves.
_build_authenticator_data_payload = response._build_authenticator_data_payload
_build_credential_overview = response._build_credential_overview
_build_credential_payload = response._build_credential_payload
_build_flag_payload = response._build_flag_payload
_collect_response_extras = response._collect_response_extras
_convert_client_data_entry = response._convert_client_data_entry

# Certificate conversion leaves.
_convert_attestation_entry_impl = certificates._convert_attestation_entry_impl
_convert_attestation_statement_impl = certificates._convert_attestation_statement_impl
_convert_certificate_bytes_impl = certificates._convert_certificate_bytes_impl
_convert_certificate_chain_impl = certificates._convert_certificate_chain_impl
_convert_certificate_payload_impl = certificates._convert_certificate_payload_impl

# Summary field formatting leaves.
_append_multiline_field = summary._append_multiline_field
_append_simple_field = summary._append_simple_field
_build_authenticator_data_lines = summary._build_authenticator_data_lines
_collect_attested_info = summary._collect_attested_info
_format_boolean = summary._format_boolean
_format_counter_value = summary._format_counter_value
_format_flag_line = summary._format_flag_line
_format_json_block = summary._format_json_block
_parse_attested_data = summary._parse_attested_data

# CTAP map classification and labels.
_GET_ASSERTION_REQUEST_LABELS = ctap._GET_ASSERTION_REQUEST_LABELS
_GET_ASSERTION_RESPONSE_LABELS = ctap._GET_ASSERTION_RESPONSE_LABELS
_MAKE_CREDENTIAL_REQUEST_LABELS = ctap._MAKE_CREDENTIAL_REQUEST_LABELS
_MAKE_CREDENTIAL_RESPONSE_LABELS = ctap._MAKE_CREDENTIAL_RESPONSE_LABELS
_build_labeled_ctap_map = ctap._build_labeled_ctap_map
_classify_ctap_map = ctap._classify_ctap_map
_format_ctap_entry_key = ctap._format_ctap_entry_key
_looks_like_get_assertion_output = ctap._looks_like_get_assertion_output
_looks_like_get_assertion_request = ctap._looks_like_get_assertion_request
_looks_like_make_credential_output = ctap._looks_like_make_credential_output
_looks_like_make_credential_request = ctap._looks_like_make_credential_request
_resolve_ctap_label = ctap._resolve_ctap_label

# CTAP field conversion leaves.
_convert_ctap_credential_descriptor = ctap._convert_ctap_credential_descriptor
_convert_optional_ctap_field = ctap._convert_optional_ctap_field

# CTAP trailing-field repair helpers.

# CTAP make-credential repair helpers.
_extract_mapping_bytes = ctap._extract_mapping_bytes
_extract_mapping_string = ctap._extract_mapping_string

# Top-level decode pipeline helpers.
_PEM_CERT_PATTERN = pipeline._PEM_CERT_PATTERN
_decode_binary_field = pipeline._decode_binary_field
_decode_binary_input = pipeline._decode_binary_input
_decode_binary_payload = pipeline._decode_binary_payload
_decode_json_object = pipeline._decode_json_object
_decode_pem_certificates = pipeline._decode_pem_certificates
_decode_public_key_credential = pipeline._decode_public_key_credential
_expand_cbor_value = pipeline._expand_cbor_value
_looks_like_pem = pipeline._looks_like_pem
_try_decode_attestation_object = pipeline._try_decode_attestation_object
_try_decode_authenticator_data = pipeline._try_decode_authenticator_data
_try_decode_certificate_bytes = pipeline._try_decode_certificate_bytes
_try_parse_json = pipeline._try_parse_json

# CTAP prefix byte and CBOR payload decoding.
_extract_ctap_prefix = ctap._extract_ctap_prefix
_is_padding_bytes = ctap._is_padding_bytes
_try_decode_cbor = ctap._try_decode_cbor

# CTAP field parsers and converters.
_convert_att_stmt_field = ctap._convert_att_stmt_field
_convert_auth_data_field = ctap._convert_auth_data_field
_convert_ctap_allow_list = ctap._convert_ctap_allow_list
_convert_ctap_user = ctap._convert_ctap_user
_convert_ctap_user_field = ctap._convert_ctap_user_field
_convert_pub_key_cred_params = ctap._convert_pub_key_cred_params
_convert_signature_field = ctap._convert_signature_field
_convert_user_text_value = ctap._convert_user_text_value
_format_att_stmt_for_expanded_json = ctap._format_att_stmt_for_expanded_json
_format_auth_data_for_expanded_json = ctap._format_auth_data_for_expanded_json
_parse_authenticator_data_bytes = ctap._parse_authenticator_data_bytes

# CTAP interpretation and expanded JSON.
_GET_ASSERTION_REQUEST_HANDLERS = ctap._GET_ASSERTION_REQUEST_HANDLERS
_GET_ASSERTION_RESPONSE_HANDLERS = ctap._GET_ASSERTION_RESPONSE_HANDLERS
_MAKE_CREDENTIAL_REQUEST_HANDLERS = ctap._MAKE_CREDENTIAL_REQUEST_HANDLERS
_MAKE_CREDENTIAL_RESPONSE_HANDLERS = ctap._MAKE_CREDENTIAL_RESPONSE_HANDLERS
_build_get_assertion_expanded_json = ctap._build_get_assertion_expanded_json
_build_get_assertion_request_expanded_json = (
    ctap._build_get_assertion_request_expanded_json
)
_build_make_credential_expanded_json = ctap._build_make_credential_expanded_json
_build_make_credential_request_expanded_json = (
    ctap._build_make_credential_request_expanded_json
)
_interpret_ctap_cbor_value = ctap._interpret_ctap_cbor_value
_interpret_get_assertion_map = ctap._interpret_get_assertion_map
_interpret_get_assertion_request_map = ctap._interpret_get_assertion_request_map
_interpret_make_credential_map = ctap._interpret_make_credential_map
_interpret_make_credential_request_map = (
    ctap._interpret_make_credential_request_map
)

# Client data and authenticator data details.
_binary_summary = pipeline._binary_summary
_build_client_data_details = pipeline._build_client_data_details
_describe_authenticator_data_bytes = pipeline._describe_authenticator_data_bytes
_describe_client_data_from_bytes = pipeline._describe_client_data_from_bytes
_extract_attestation_certificate = pipeline._extract_attestation_certificate
_is_client_data_dict = pipeline._is_client_data_dict
_is_public_key_credential = pipeline._is_public_key_credential
_parse_attestation_object = pipeline._parse_attestation_object
_try_decode_utf8 = pipeline._try_decode_utf8

# Decoder payload and result conversion.
_build_authenticator_section = response._build_authenticator_section
_build_decoder_payload = response._build_decoder_payload
_convert_attestation_entry = response._convert_attestation_entry
_convert_attestation_object_data = response._convert_attestation_object_data
_convert_attestation_statement = response._convert_attestation_statement
_convert_authenticator_data_result = response._convert_authenticator_data_result
_convert_certificate_bytes = response._convert_certificate_bytes
_convert_certificate_chain = response._convert_certificate_chain
_convert_certificate_payload = response._convert_certificate_payload
_convert_certificate_result = response._convert_certificate_result
_convert_client_data_result = response._convert_client_data_result
_convert_public_key_credential_data = response._convert_public_key_credential_data
_convert_result_to_data = response._convert_result_to_data
_prepare_decoder_response = response._prepare_decoder_response

# Summary rendering.
_base_type = summary._base_type
_build_certificate_summary_lines = summary._build_certificate_summary_lines
_extend_with_attestation_section = summary._extend_with_attestation_section
_extend_with_authenticator_details = summary._extend_with_authenticator_details
_extend_with_authenticator_extensions = summary._extend_with_authenticator_extensions
_extend_with_client_data_details = summary._extend_with_client_data_details
_extend_with_client_data_entry = summary._extend_with_client_data_entry
_extend_with_client_extensions = summary._extend_with_client_extensions
_format_attestation_object_summary = summary._format_attestation_object_summary
_format_authenticator_data_summary = summary._format_authenticator_data_summary
_format_cbor_summary = summary._format_cbor_summary
_format_certificate_summary = summary._format_certificate_summary
_format_client_data_summary = summary._format_client_data_summary
_format_generic_summary = summary._format_generic_summary
_format_json_summary = summary._format_json_summary
_format_public_key_credential_summary = summary._format_public_key_credential_summary
_format_result_summary = summary._format_result_summary
