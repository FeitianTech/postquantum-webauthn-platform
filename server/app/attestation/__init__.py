"""Attestation and credential helper utilities.

The implementation lives in this package's submodules; this module is the public
face of it and re-exports the pieces callers use. Each fragment
resolves its own names through its own imports, so a name here is the same
object the fragment defines -- patching one of these re-exports changes what
callers of *this module* see, not what the fragments call.
"""
from __future__ import annotations

from .. import config
from . import (
    aaguid_leaf,
    certificates,
    checks,
    classical_runtime,
    encoding_leaf,
    pqc_constraints_runtime,
    pqc_runtime,
    runtime_state,
    trust,
    trust_ca_runtime,
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
_derive_certificate_algorithm_info = certificates._derive_certificate_algorithm_info
_extract_common_names = certificates._extract_common_names
_format_algorithm_component = certificates._format_algorithm_component
_format_hash_value = certificates._format_hash_value
_normalise_signature_algorithm_name = certificates._normalise_signature_algorithm_name
format_x509_name = certificates.format_x509_name

# Certificate extension serialisation.
_parse_fido_transport_bitfield = certificates._parse_fido_transport_bitfield
_serialize_extension_value = certificates._serialize_extension_value

# Public-key serialisation.
_build_unknown_public_key_info = certificates._build_unknown_public_key_info
_serialize_public_key_info = certificates._serialize_public_key_info

# Certificate summary composition.
_build_certificate_summary = certificates._build_certificate_summary

# Full certificate serialisation.
_serialize_attestation_certificate_fallback = certificates._serialize_attestation_certificate_fallback
serialize_attestation_certificate = certificates.serialize_attestation_certificate

# Attestation payload certificate extraction.
_coerce_attestation_certificate_bytes = certificates._coerce_attestation_certificate_bytes
extract_attestation_details = certificates.extract_attestation_details

# Trust-path, AAGUID, and certificate validity helpers.
_certificate_datetime = trust._certificate_datetime
_coerce_bytes = trust._coerce_bytes
_coerce_certificate_bytes = trust._coerce_certificate_bytes
_collect_metadata_root_certificates = trust._collect_metadata_root_certificates
_collect_trust_path_entries = trust._collect_trust_path_entries
_describe_certificate_subject = trust._describe_certificate_subject
_ensure_utc_datetime = trust._ensure_utc_datetime
_extract_attestation_leaf_certificate = trust._extract_attestation_leaf_certificate
_extract_certificate_aaguid = trust._extract_certificate_aaguid
_find_metadata_entry_for_aaguid = trust._find_metadata_entry_for_aaguid
_resolve_root_validity = trust._resolve_root_validity

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
_collect_allowed_algorithms = checks._collect_allowed_algorithms
_resolve_uv_required = checks._resolve_uv_required

# Client data and authenticator data checks.
_coerce_expected_bytes = checks._coerce_expected_bytes
_populate_authenticator_data_results = checks._populate_authenticator_data_results
_populate_client_data_results = checks._populate_client_data_results
_populate_rp_id_hash_result = checks._populate_rp_id_hash_result
_resolve_expected_challenge = checks._resolve_expected_challenge

# Attestation signature and root checks.
_collect_attestation_trust_path = checks._collect_attestation_trust_path
_evaluate_root_validation = checks._evaluate_root_validation
_resolve_signature_validation = checks._resolve_signature_validation

# Metadata result finalisation.
_finalize_metadata_results = checks._finalize_metadata_results

# The attestation check orchestrator.
perform_attestation_checks = checks.perform_attestation_checks
