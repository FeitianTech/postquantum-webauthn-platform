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
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

from fido2.attestation import (
    Attestation,
    AttestationResult,
    AttestationType,
    InvalidData,
    InvalidSignature,
    UnsupportedType,
    verify_x509_chain,
)
from fido2.attestation.base import TrustPathEvaluation
from fido2.attestation.base import _verify_mldsa_certificate_signature
from fido2.cose import (
    CoseKey,
    describe_mldsa_oid,
    describe_mldsa_oid_name,
    extract_certificate_public_key_info,
)
from fido2.utils import ByteBuffer, websafe_decode
from fido2.webauthn import (
    AuthenticatorData,
    AttestationObject,
    CollectedClientData,
    RegistrationResponse,
    Aaguid,
)
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from .config import app
from .metadata import get_mds_verifier, metadata_entry_trust_anchor_status
from .pqc import PQC_ALGORITHM_ID_TO_NAME, is_pqc_algorithm
from .attestation_parts.encoding_leaf import (
    colon_hex,
    decode_asn1_octet_string,
    encode_base64url,
    format_hex_bytes_lines,
    format_hex_string_lines,
    make_json_safe,
)
from .attestation_parts.aaguid_leaf import CRED_PROTECT_LABELS
from .attestation_parts import aaguid_leaf as _aaguid_leaf
from .attestation_parts import trust_runtime as _trust_runtime
from .attestation_parts import trust_ca_runtime as _trust_ca_runtime
from .attestation_parts import pqc_runtime as _pqc_runtime
from .attestation_parts import pqc_constraints_runtime as _pqc_constraints_runtime
from .attestation_parts import classical_runtime as _classical_runtime
from .attestation_parts import certificate_details_runtime as _certificate_details_runtime
from .attestation_parts import certificate_signature_leaf as _certificate_signature_leaf
from .attestation_parts import certificate_public_key_leaf as _certificate_public_key_leaf
from .attestation_parts import certificate_extensions_leaf as _certificate_extensions_leaf
from .attestation_parts import certificate_summary_runtime as _certificate_summary_runtime
from .attestation_parts import certificate_serialize_runtime as _certificate_serialize_runtime
from .attestation_parts import checks_input_runtime as _checks_input_runtime
from .attestation_parts import checks_policy_runtime as _checks_policy_runtime
from .attestation_parts import checks_attestation_runtime as _checks_attestation_runtime
from .attestation_parts import checks_metadata_runtime as _checks_metadata_runtime
from .attestation_parts import checks_runtime as _checks_runtime

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

AAGUID_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

EXTENSION_DISPLAY_METADATA: Dict[str, Dict[str, Any]] = {
    "1.3.6.1.4.1.41482.13.1": {
        "friendly_name": "Yubico: Firmware version",
    },
    "1.3.6.1.4.1.41482.2": {
        "friendly_name": "Yubico: Device identifier",
    },
    "1.3.6.1.4.1.41482.1.1": {
        "friendly_name": "Security Key by Yubico Series",
    },
    "1.3.6.1.4.1.45724.1.1.4": {
        "friendly_name": "FIDO: Device AAGUID",
    },
    "1.3.6.1.4.1.45724.2.1.1": {
        "friendly_name": "FIDO: Transports",
    },
    "2.5.29.14": {
        "friendly_name": "Subject key id",
    },
    "2.5.29.35": {
        "friendly_name": "Authority key identifier",
    },
    "2.5.29.19": {
        "friendly_name": "X509v3 Basic Constraints",
        "header": "X509v3 Basic Constraints",
        "include_oid_in_header": False,
    },
}

_PQC_ALGORITHM_NAME_TO_ID = {
    name.lower(): alg_id for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items()
}
_HASH_NORMALISE_PATTERN = _certificate_signature_leaf._HASH_NORMALISE_PATTERN

_RUNTIME_REBOUND_CACHE: Dict[Callable[..., Any], Callable[..., Any]] = {}


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


_AAGUID_LEAF_BINDINGS: Dict[str, Callable[..., Any]] = {
    "describe_cred_protect": _aaguid_leaf.describe_cred_protect,
    "coerce_non_negative_int": _aaguid_leaf.coerce_non_negative_int,
    "normalize_aaguid_string": _aaguid_leaf.normalize_aaguid_string,
    "coerce_aaguid_hex": _aaguid_leaf.coerce_aaguid_hex,
    "augment_aaguid_fields": _aaguid_leaf.augment_aaguid_fields,
    "extract_min_pin_length": _aaguid_leaf.extract_min_pin_length,
    "summarize_authenticator_extensions": _aaguid_leaf.summarize_authenticator_extensions,
}

_TRUST_RUNTIME_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_ensure_utc_datetime": _trust_runtime._ensure_utc_datetime,
    "_certificate_datetime": _trust_runtime._certificate_datetime,
    "_coerce_bytes": _trust_runtime._coerce_bytes,
    "_collect_trust_path_entries": _trust_runtime._collect_trust_path_entries,
    "_extract_certificate_aaguid": _trust_runtime._extract_certificate_aaguid,
    "_coerce_certificate_bytes": _trust_runtime._coerce_certificate_bytes,
    "_extract_attestation_leaf_certificate": _trust_runtime._extract_attestation_leaf_certificate,
    "_collect_metadata_root_certificates": _trust_runtime._collect_metadata_root_certificates,
    "_find_metadata_entry_for_aaguid": _trust_runtime._find_metadata_entry_for_aaguid,
    "_resolve_root_validity": _trust_runtime._resolve_root_validity,
    "_describe_certificate_subject": _trust_runtime._describe_certificate_subject,
}

_TRUST_CA_RUNTIME_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_trusted_ca_subjects": _trust_ca_runtime._trusted_ca_subjects,
    "_trusted_ca_fingerprints": _trust_ca_runtime._trusted_ca_fingerprints,
    "_certificate_fingerprint": _trust_ca_runtime._certificate_fingerprint,
    "_is_trusted_ca_certificate": _trust_ca_runtime._is_trusted_ca_certificate,
}

_PQC_RUNTIME_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_evaluate_mldsa_attestation_root": _pqc_runtime._evaluate_mldsa_attestation_root,
    "_attempt_pqc_attestation_signature_validation": _pqc_runtime._attempt_pqc_attestation_signature_validation,
}

_PQC_CONSTRAINTS_RUNTIME_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_normalise_pqc_algorithm_identifier": _pqc_constraints_runtime._normalise_pqc_algorithm_identifier,
    "_check_pqc_certificate_constraints": _pqc_constraints_runtime._check_pqc_certificate_constraints,
    "_verify_pqc_attestation_chain": _pqc_constraints_runtime._verify_pqc_attestation_chain,
}

_CLASSICAL_RUNTIME_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_evaluate_classical_attestation_root": _classical_runtime._evaluate_classical_attestation_root,
}

_CERTIFICATE_BINDINGS: Dict[str, Callable[..., Any]] = {
    "format_x509_name": _certificate_signature_leaf.format_x509_name,
    "_format_algorithm_component": _certificate_signature_leaf._format_algorithm_component,
    "_format_hash_value": _certificate_signature_leaf._format_hash_value,
    "_normalise_signature_algorithm_name": _certificate_signature_leaf._normalise_signature_algorithm_name,
    "_derive_certificate_algorithm_info": _certificate_signature_leaf._derive_certificate_algorithm_info,
    "_extract_common_names": _certificate_signature_leaf._extract_common_names,
    "_load_oqs_signature_details": _certificate_public_key_leaf._load_oqs_signature_details,
    "_build_unknown_public_key_info": _certificate_public_key_leaf._build_unknown_public_key_info,
    "_serialize_public_key_info": _certificate_public_key_leaf._serialize_public_key_info,
    "_serialize_extension_value": _certificate_extensions_leaf._serialize_extension_value,
    "_parse_fido_transport_bitfield": _certificate_extensions_leaf._parse_fido_transport_bitfield,
    "_build_certificate_summary": _certificate_summary_runtime._build_certificate_summary,
    "_coerce_attestation_certificate_bytes": _certificate_details_runtime._coerce_attestation_certificate_bytes,
    "extract_attestation_details": _certificate_details_runtime.extract_attestation_details,
    "_serialize_attestation_certificate_fallback": _certificate_serialize_runtime._serialize_attestation_certificate_fallback,
    "serialize_attestation_certificate": _certificate_serialize_runtime.serialize_attestation_certificate,
}

_CHECKS_BINDINGS: Dict[str, Callable[..., Any]] = {
    "_coerce_expected_bytes": _checks_input_runtime._coerce_expected_bytes,
    "_resolve_expected_challenge": _checks_input_runtime._resolve_expected_challenge,
    "_populate_client_data_results": _checks_input_runtime._populate_client_data_results,
    "_populate_rp_id_hash_result": _checks_input_runtime._populate_rp_id_hash_result,
    "_resolve_uv_required": _checks_policy_runtime._resolve_uv_required,
    "_collect_allowed_algorithms": _checks_policy_runtime._collect_allowed_algorithms,
    "_populate_authenticator_data_results": _checks_input_runtime._populate_authenticator_data_results,
    "_resolve_signature_validation": _checks_attestation_runtime._resolve_signature_validation,
    "_collect_attestation_trust_path": _checks_attestation_runtime._collect_attestation_trust_path,
    "_evaluate_root_validation": _checks_attestation_runtime._evaluate_root_validation,
    "_finalize_metadata_results": _checks_metadata_runtime._finalize_metadata_results,
    "perform_attestation_checks": _checks_runtime.perform_attestation_checks,
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
