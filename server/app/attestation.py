"""Attestation and credential helper utilities."""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import string
import textwrap
import types
import uuid
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from fido2.attestation import (
    Attestation,
    AttestationResult,
    AttestationType,
    InvalidData,
    InvalidSignature,
    UnsupportedType,
    verify_x509_chain,
)
from fido2.attestation.base import (
    TrustPathEvaluation,
    _verify_mldsa_certificate_signature,
)
from fido2.cose import (
    CoseKey,
    describe_mldsa_oid,
    describe_mldsa_oid_name,
    extract_certificate_public_key_info,
)
from fido2.utils import ByteBuffer, websafe_decode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    RegistrationResponse,
)

from . import metadata
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
from .attestation_parts.aaguid_leaf import CRED_PROTECT_LABELS
from .attestation_parts.encoding_leaf import (
    colon_hex,
    decode_asn1_octet_string,
    encode_base64url,
    format_hex_bytes_lines,
    format_hex_string_lines,
    make_json_safe,
)
from .config import app
from .metadata import get_mds_verifier, metadata_entry_trust_anchor_status
from .pqc import PQC_ALGORITHM_ID_TO_NAME, is_pqc_algorithm

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

# Constants shared with the fragments.
AAGUID_EXTENSION_OID = runtime_state.AAGUID_EXTENSION_OID
EXTENSION_DISPLAY_METADATA = runtime_state.EXTENSION_DISPLAY_METADATA

_PQC_ALGORITHM_NAME_TO_ID = pqc_constraints_runtime._PQC_ALGORITHM_NAME_TO_ID
_HASH_NORMALISE_PATTERN = certificate_signature_leaf._HASH_NORMALISE_PATTERN

_RUNTIME_REBOUND_CACHE: dict[Callable[..., Any], Callable[..., Any]] = {}


def _run_with_attestation_globals(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    rebound = _RUNTIME_REBOUND_CACHE.get(func)
    if rebound is None:
        rebound = types.FunctionType(
            func.__code__,
            globals(),
            name=func.__name__,
            argdefs=func.__defaults__,
            closure=func.__closure__,
        )
        rebound.__kwdefaults__ = getattr(func, "__kwdefaults__", None)
        _RUNTIME_REBOUND_CACHE[func] = rebound
    return rebound(*args, **kwargs)


def _bind_runtime_function(func: Callable[..., Any]) -> Callable[..., Any]:
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        return _run_with_attestation_globals(func, *args, **kwargs)

    return _wrapped


def _install_runtime_bindings(bindings: Mapping[str, Callable[..., Any]]) -> None:
    for _name, _func in bindings.items():
        globals()[_name] = _bind_runtime_function(_func)


_AAGUID_LEAF_BINDINGS: dict[str, Callable[..., Any]] = {
    "describe_cred_protect": aaguid_leaf.describe_cred_protect,
    "coerce_non_negative_int": aaguid_leaf.coerce_non_negative_int,
    "normalize_aaguid_string": aaguid_leaf.normalize_aaguid_string,
    "coerce_aaguid_hex": aaguid_leaf.coerce_aaguid_hex,
    "augment_aaguid_fields": aaguid_leaf.augment_aaguid_fields,
    "extract_min_pin_length": aaguid_leaf.extract_min_pin_length,
    "summarize_authenticator_extensions": aaguid_leaf.summarize_authenticator_extensions,
}

_TRUST_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_ensure_utc_datetime": trust_runtime._ensure_utc_datetime,
    "_certificate_datetime": trust_runtime._certificate_datetime,
    "_coerce_bytes": trust_runtime._coerce_bytes,
    "_collect_trust_path_entries": trust_runtime._collect_trust_path_entries,
    "_extract_certificate_aaguid": trust_runtime._extract_certificate_aaguid,
    "_coerce_certificate_bytes": trust_runtime._coerce_certificate_bytes,
    "_extract_attestation_leaf_certificate": trust_runtime._extract_attestation_leaf_certificate,
    "_collect_metadata_root_certificates": trust_runtime._collect_metadata_root_certificates,
    "_find_metadata_entry_for_aaguid": trust_runtime._find_metadata_entry_for_aaguid,
    "_resolve_root_validity": trust_runtime._resolve_root_validity,
    "_describe_certificate_subject": trust_runtime._describe_certificate_subject,
}

_TRUST_CA_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_trusted_ca_subjects": trust_ca_runtime._trusted_ca_subjects,
    "_trusted_ca_fingerprints": trust_ca_runtime._trusted_ca_fingerprints,
    "_certificate_fingerprint": trust_ca_runtime._certificate_fingerprint,
    "_is_trusted_ca_certificate": trust_ca_runtime._is_trusted_ca_certificate,
}

_PQC_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_evaluate_mldsa_attestation_root": pqc_runtime._evaluate_mldsa_attestation_root,
    "_attempt_pqc_attestation_signature_validation": pqc_runtime._attempt_pqc_attestation_signature_validation,
}

_PQC_CONSTRAINTS_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_normalise_pqc_algorithm_identifier": pqc_constraints_runtime._normalise_pqc_algorithm_identifier,
    "_check_pqc_certificate_constraints": pqc_constraints_runtime._check_pqc_certificate_constraints,
    "_verify_pqc_attestation_chain": pqc_constraints_runtime._verify_pqc_attestation_chain,
}

_CLASSICAL_RUNTIME_BINDINGS: dict[str, Callable[..., Any]] = {
    "_evaluate_classical_attestation_root": classical_runtime._evaluate_classical_attestation_root,
}

_CERTIFICATE_BINDINGS: dict[str, Callable[..., Any]] = {
    "format_x509_name": certificate_signature_leaf.format_x509_name,
    "_format_algorithm_component": certificate_signature_leaf._format_algorithm_component,
    "_format_hash_value": certificate_signature_leaf._format_hash_value,
    "_normalise_signature_algorithm_name": certificate_signature_leaf._normalise_signature_algorithm_name,
    "_derive_certificate_algorithm_info": certificate_signature_leaf._derive_certificate_algorithm_info,
    "_extract_common_names": certificate_signature_leaf._extract_common_names,
    "_build_unknown_public_key_info": certificate_public_key_leaf._build_unknown_public_key_info,
    "_serialize_public_key_info": certificate_public_key_leaf._serialize_public_key_info,
    "_serialize_extension_value": certificate_extensions_leaf._serialize_extension_value,
    "_parse_fido_transport_bitfield": certificate_extensions_leaf._parse_fido_transport_bitfield,
    "_build_certificate_summary": certificate_summary_runtime._build_certificate_summary,
    "_coerce_attestation_certificate_bytes": certificate_details_runtime._coerce_attestation_certificate_bytes,
    "extract_attestation_details": certificate_details_runtime.extract_attestation_details,
    "_serialize_attestation_certificate_fallback": certificate_serialize_runtime._serialize_attestation_certificate_fallback,
    "serialize_attestation_certificate": certificate_serialize_runtime.serialize_attestation_certificate,
}

_CHECKS_BINDINGS: dict[str, Callable[..., Any]] = {
    "_coerce_expected_bytes": checks_input_runtime._coerce_expected_bytes,
    "_resolve_expected_challenge": checks_input_runtime._resolve_expected_challenge,
    "_populate_client_data_results": checks_input_runtime._populate_client_data_results,
    "_populate_rp_id_hash_result": checks_input_runtime._populate_rp_id_hash_result,
    "_resolve_uv_required": checks_policy_runtime._resolve_uv_required,
    "_collect_allowed_algorithms": checks_policy_runtime._collect_allowed_algorithms,
    "_populate_authenticator_data_results": checks_input_runtime._populate_authenticator_data_results,
    "_resolve_signature_validation": checks_attestation_runtime._resolve_signature_validation,
    "_collect_attestation_trust_path": checks_attestation_runtime._collect_attestation_trust_path,
    "_evaluate_root_validation": checks_attestation_runtime._evaluate_root_validation,
    "_finalize_metadata_results": checks_metadata_runtime._finalize_metadata_results,
    "perform_attestation_checks": checks_runtime.perform_attestation_checks,
}

_install_runtime_bindings(
    {
        **_AAGUID_LEAF_BINDINGS,
        **_TRUST_RUNTIME_BINDINGS,
        **_TRUST_CA_RUNTIME_BINDINGS,
        **_PQC_RUNTIME_BINDINGS,
        **_PQC_CONSTRAINTS_RUNTIME_BINDINGS,
        **_CLASSICAL_RUNTIME_BINDINGS,
        **_CERTIFICATE_BINDINGS,
        **_CHECKS_BINDINGS,
    }
)
