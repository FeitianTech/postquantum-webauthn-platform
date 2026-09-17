"""Attestation and credential helper utilities.

The implementation lives in :mod:`server.app.attestation_parts`; this module is
the public face of it and re-exports the pieces callers use. Each fragment
resolves its own names through its own imports, so a name here is the same
object the fragment defines -- patching one of these re-exports changes what
callers of *this module* see, not what the fragments call.
"""
from __future__ import annotations

from . import config
from .attestation_parts import (
    aaguid_leaf,
    certificate_details_runtime,
    certificate_extensions_leaf,
    certificate_public_key_leaf,
    certificate_serialize_runtime,
    certificate_signature_leaf,
    certificate_summary_runtime,
    checks_attestation_runtime,
    checks_input_runtime,
    checks_metadata_runtime,
    checks_policy_runtime,
    checks_runtime,
    classical_runtime,
    encoding_leaf,
    pqc_constraints_runtime,
    pqc_runtime,
    runtime_state,
    trust_ca_runtime,
    trust_runtime,
)

__all__ = [
    "CRED_PROTECT_LABELS",
    "EXTENSION_DISPLAY_METADATA",
    "augment_aaguid_fields",
    "coerce_aaguid_hex",
    "describe_cred_protect",
    "encode_base64url",
    "extract_attestation_details",
    "extract_min_pin_length",
    "format_hex_bytes_lines",
    "make_json_safe",
    "perform_attestation_checks",
    "serialize_attestation_certificate",
    "summarize_authenticator_extensions",
]

# The Flask application, reached by the trusted-CA helpers through ``config``.
app = config.app

# Constants shared with the fragments.
AAGUID_EXTENSION_OID = runtime_state.AAGUID_EXTENSION_OID
EXTENSION_DISPLAY_METADATA = runtime_state.EXTENSION_DISPLAY_METADATA
_PQC_ALGORITHM_NAME_TO_ID = pqc_constraints_runtime._PQC_ALGORITHM_NAME_TO_ID
CRED_PROTECT_LABELS = aaguid_leaf.CRED_PROTECT_LABELS

# AAGUID, CredProtect, and authenticator extension helpers.
augment_aaguid_fields = aaguid_leaf.augment_aaguid_fields
coerce_aaguid_hex = aaguid_leaf.coerce_aaguid_hex
coerce_non_negative_int = aaguid_leaf.coerce_non_negative_int
describe_cred_protect = aaguid_leaf.describe_cred_protect
extract_min_pin_length = aaguid_leaf.extract_min_pin_length
normalize_aaguid_string = aaguid_leaf.normalize_aaguid_string
summarize_authenticator_extensions = aaguid_leaf.summarize_authenticator_extensions

# Hex, base64url, and JSON encoding helpers.
colon_hex = encoding_leaf.colon_hex
decode_asn1_octet_string = encoding_leaf.decode_asn1_octet_string
encode_base64url = encoding_leaf.encode_base64url
format_hex_bytes_lines = encoding_leaf.format_hex_bytes_lines
format_hex_string_lines = encoding_leaf.format_hex_string_lines
make_json_safe = encoding_leaf.make_json_safe

# X.509 name and signature-algorithm helpers.
_derive_certificate_algorithm_info = certificate_signature_leaf._derive_certificate_algorithm_info
_extract_common_names = certificate_signature_leaf._extract_common_names
_format_algorithm_component = certificate_signature_leaf._format_algorithm_component
_format_hash_value = certificate_signature_leaf._format_hash_value
_normalise_signature_algorithm_name = certificate_signature_leaf._normalise_signature_algorithm_name
format_x509_name = certificate_signature_leaf.format_x509_name

# Certificate extension serialisation.
_parse_fido_transport_bitfield = certificate_extensions_leaf._parse_fido_transport_bitfield
_serialize_extension_value = certificate_extensions_leaf._serialize_extension_value

# Public-key serialisation.
_build_unknown_public_key_info = certificate_public_key_leaf._build_unknown_public_key_info
_serialize_public_key_info = certificate_public_key_leaf._serialize_public_key_info

# Certificate summary composition.
_build_certificate_summary = certificate_summary_runtime._build_certificate_summary

# Full certificate serialisation.
_serialize_attestation_certificate_fallback = certificate_serialize_runtime._serialize_attestation_certificate_fallback
serialize_attestation_certificate = certificate_serialize_runtime.serialize_attestation_certificate

# Attestation payload certificate extraction.
_coerce_attestation_certificate_bytes = certificate_details_runtime._coerce_attestation_certificate_bytes
extract_attestation_details = certificate_details_runtime.extract_attestation_details

# Trust-path, AAGUID, and certificate validity helpers.
_certificate_datetime = trust_runtime._certificate_datetime
_coerce_bytes = trust_runtime._coerce_bytes
_coerce_certificate_bytes = trust_runtime._coerce_certificate_bytes
_collect_metadata_root_certificates = trust_runtime._collect_metadata_root_certificates
_collect_trust_path_entries = trust_runtime._collect_trust_path_entries
_describe_certificate_subject = trust_runtime._describe_certificate_subject
_ensure_utc_datetime = trust_runtime._ensure_utc_datetime
_extract_attestation_leaf_certificate = trust_runtime._extract_attestation_leaf_certificate
_extract_certificate_aaguid = trust_runtime._extract_certificate_aaguid
_find_metadata_entry_for_aaguid = trust_runtime._find_metadata_entry_for_aaguid
_resolve_root_validity = trust_runtime._resolve_root_validity

# Trusted-CA allowlist helpers.
_certificate_fingerprint = trust_ca_runtime._certificate_fingerprint
_is_trusted_ca_certificate = trust_ca_runtime._is_trusted_ca_certificate
_trusted_ca_fingerprints = trust_ca_runtime._trusted_ca_fingerprints
_trusted_ca_subjects = trust_ca_runtime._trusted_ca_subjects

# Classical attestation root evaluation.
_evaluate_classical_attestation_root = classical_runtime._evaluate_classical_attestation_root

# PQC certificate constraint checks.
_check_pqc_certificate_constraints = pqc_constraints_runtime._check_pqc_certificate_constraints
_normalise_pqc_algorithm_identifier = pqc_constraints_runtime._normalise_pqc_algorithm_identifier
_verify_pqc_attestation_chain = pqc_constraints_runtime._verify_pqc_attestation_chain

# PQC attestation root and signature evaluation.
_attempt_pqc_attestation_signature_validation = pqc_runtime._attempt_pqc_attestation_signature_validation
_evaluate_mldsa_attestation_root = pqc_runtime._evaluate_mldsa_attestation_root

# Registration policy resolution.
_collect_allowed_algorithms = checks_policy_runtime._collect_allowed_algorithms
_resolve_uv_required = checks_policy_runtime._resolve_uv_required

# Client data and authenticator data checks.
_coerce_expected_bytes = checks_input_runtime._coerce_expected_bytes
_populate_authenticator_data_results = checks_input_runtime._populate_authenticator_data_results
_populate_client_data_results = checks_input_runtime._populate_client_data_results
_populate_rp_id_hash_result = checks_input_runtime._populate_rp_id_hash_result
_resolve_expected_challenge = checks_input_runtime._resolve_expected_challenge

# Attestation signature and root checks.
_collect_attestation_trust_path = checks_attestation_runtime._collect_attestation_trust_path
_evaluate_root_validation = checks_attestation_runtime._evaluate_root_validation
_resolve_signature_validation = checks_attestation_runtime._resolve_signature_validation

# Metadata result finalisation.
_finalize_metadata_results = checks_metadata_runtime._finalize_metadata_results

# The attestation check orchestrator.
perform_attestation_checks = checks_runtime.perform_attestation_checks
