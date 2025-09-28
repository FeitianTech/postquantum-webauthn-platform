# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import base64
import hashlib
import json

from dataclasses import dataclass

from .utils import ByteBuffer, bytes2int, int2bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519, types
from typing import (
    Sequence,
    Type,
    Mapping,
    Any,
    TypeVar,
    Optional,
    Iterable,
    Dict,
    Callable,
    Set,
    List,
    Tuple,
)

try:  # pragma: no cover - exercised indirectly in tests
    import oqs  # type: ignore
except (ImportError, SystemExit) as _oqs_error:  # pragma: no cover - handled in verification
    oqs = None  # type: ignore
    _oqs_import_error: Optional[BaseException] = _oqs_error
else:  # pragma: no cover - module imported successfully
    _oqs_import_error = None


def _require_oqs():  # pragma: no cover - exercised in tests when oqs is missing
    if oqs is not None:  # type: ignore[name-defined]
        return oqs  # type: ignore[return-value]
    message = (
        "ML-DSA verification requires the 'oqs' package. Install the "
        "python-fido2-webauthn-test[pqc] extra to enable post-quantum algorithms."
    )
    raise RuntimeError(message) from _oqs_import_error


def _get_optional_oqs():
    """Return the oqs module when available without raising."""

    return oqs  # type: ignore[name-defined,return-value]


def _parse_der_length(data: memoryview, idx: int) -> tuple[int, int]:
    """Parse a DER length field and return (length, new_index)."""

    if idx >= len(data):
        raise ValueError("Invalid DER length: truncated data")
    first = data[idx]
    idx += 1
    if first & 0x80 == 0:
        return first, idx
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length DER encodings are not supported")
    if idx + num_bytes > len(data):
        raise ValueError("Invalid DER length: truncated data")
    length = int.from_bytes(data[idx : idx + num_bytes], "big")
    idx += num_bytes
    return length, idx


def _extract_subject_public_key_from_spki(spki_der: bytes) -> bytes:
    """Extract the BIT STRING payload from a SubjectPublicKeyInfo structure."""

    view = memoryview(spki_der)
    idx = 0
    if not view:
        raise ValueError("Empty SubjectPublicKeyInfo structure")
    if view[idx] != 0x30:
        raise ValueError("SubjectPublicKeyInfo must be a SEQUENCE")
    idx += 1
    seq_len, idx = _parse_der_length(view, idx)
    end_of_spki = idx + seq_len
    if end_of_spki > len(view):
        raise ValueError("SubjectPublicKeyInfo length exceeds buffer size")

    if idx >= end_of_spki or view[idx] != 0x30:
        raise ValueError("AlgorithmIdentifier must be present in SubjectPublicKeyInfo")
    idx += 1
    algo_len, idx = _parse_der_length(view, idx)
    idx += algo_len
    if idx > end_of_spki:
        raise ValueError("AlgorithmIdentifier overruns SubjectPublicKeyInfo")

    if idx >= end_of_spki or view[idx] != 0x03:
        raise ValueError("SubjectPublicKeyInfo must contain a BIT STRING public key")
    idx += 1
    bitstring_len, idx = _parse_der_length(view, idx)
    if idx + bitstring_len > end_of_spki:
        raise ValueError("SubjectPublicKey BIT STRING overruns SubjectPublicKeyInfo")
    if bitstring_len == 0:
        raise ValueError("SubjectPublicKey BIT STRING is empty")

    unused_bits = view[idx]
    idx += 1
    payload = bytes(view[idx : idx + bitstring_len - 1])
    if unused_bits != 0:
        raise ValueError("Unsupported SubjectPublicKey BIT STRING padding")
    return payload


def _find_mldsa_der_candidate(
    view: memoryview,
    start: int,
    end: int,
    expected_length: int,
    depth: int = 8,
) -> Optional[bytes]:
    """Recursively search DER structures for an OCTET STRING of the given length."""

    if depth <= 0:
        return None

    idx = start
    while idx < end:
        if idx >= len(view):
            return None
        tag = view[idx]
        idx += 1
        try:
            length, idx = _parse_der_length(view, idx)
        except Exception:
            return None

        content_end = idx + length
        if content_end > end:
            return None

        content_view = view[idx:content_end]
        if len(content_view) == expected_length:
            return bytes(content_view)

        candidate: Optional[bytes] = None
        if tag in (0x30, 0x31):  # SEQUENCE or SET
            candidate = _find_mldsa_der_candidate(
                view, idx, content_end, expected_length, depth - 1
            )
        elif tag == 0x04:  # OCTET STRING
            candidate = _find_mldsa_der_candidate(
                content_view, 0, len(content_view), expected_length, depth - 1
            )
        elif tag == 0x03 and length > 0:  # BIT STRING
            if content_view[0] == 0x00:
                candidate = _find_mldsa_der_candidate(
                    content_view, 1, len(content_view), expected_length, depth - 1
                )

        if candidate is not None:
            return candidate

        idx = content_end

    return None


def _unwrap_mldsa_subject_public_key(
    payload: bytes, parameter_set: Optional[str] = None
) -> tuple[bytes, Optional[bytes]]:
    """Return raw ML-DSA public key bytes, stripping DER wrappers when present."""

    if not payload:
        return payload, None

    original = payload
    view = memoryview(payload)

    try:
        if view[0] == 0x04:  # OCTET STRING
            length, idx = _parse_der_length(view, 1)
            end = idx + length
            if end == len(view):
                payload = bytes(view[idx:end])
                return payload, original
        elif view[0] == 0x30:  # SEQUENCE
            idx = 1
            seq_length, idx = _parse_der_length(view, idx)
            seq_end = idx + seq_length
            if seq_end == len(view):
                while idx < seq_end:
                    tag = view[idx]
                    idx += 1
                    element_length, idx = _parse_der_length(view, idx)
                    element_end = idx + element_length
                    if element_end > seq_end:
                        break
                    if tag == 0x04:  # OCTET STRING inside SEQUENCE
                        candidate = bytes(view[idx:element_end])
                        unwrapped, _ = _unwrap_mldsa_subject_public_key(
                            candidate, parameter_set
                        )
                        return unwrapped, original
                    idx = element_end
    except Exception:
        pass

    expected_length: Optional[int] = None
    if parameter_set:
        parameter_details = _get_mldsa_parameter_details(parameter_set)
        expected_length = parameter_details.get("public_key_length")

    if expected_length and len(payload) != expected_length:
        candidate = _find_mldsa_der_candidate(view, 0, len(view), expected_length)
        if candidate is not None:
            return candidate, original

    return payload, None


def _skip_der_value(view: memoryview, idx: int) -> int:
    """Advance *idx* past a single DER element."""

    if idx >= len(view):
        raise ValueError("Truncated DER element")
    idx += 1
    length, idx = _parse_der_length(view, idx)
    end = idx + length
    if end > len(view):
        raise ValueError("DER element overruns buffer")
    return end


def _decode_der_oid(view: memoryview, idx: int) -> tuple[str, int]:
    """Decode an OBJECT IDENTIFIER at *idx* returning dotted string and new index."""

    if idx >= len(view) or view[idx] != 0x06:
        raise ValueError("Expected OBJECT IDENTIFIER")
    idx += 1
    length, idx = _parse_der_length(view, idx)
    end = idx + length
    if end > len(view) or length <= 0:
        raise ValueError("Invalid OBJECT IDENTIFIER length")

    body = view[idx:end]
    idx = end

    first = body[0]
    oid_numbers = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            continue
        oid_numbers.append(str(value))
        value = 0
    if body[-1] & 0x80:
        raise ValueError("Invalid OBJECT IDENTIFIER continuation byte")
    if value:
        oid_numbers.append(str(value))
    return ".".join(oid_numbers), idx


def _parse_spki_algorithm_info(spki_der: bytes) -> tuple[str, Optional[bytes]]:
    """Return (OID, parameters) from a SubjectPublicKeyInfo structure."""

    view = memoryview(spki_der)
    idx = 0
    if not view or view[idx] != 0x30:
        raise ValueError("SubjectPublicKeyInfo must be a SEQUENCE")
    idx += 1
    total_len, idx = _parse_der_length(view, idx)
    end = idx + total_len
    if end > len(view):
        raise ValueError("SubjectPublicKeyInfo length exceeds buffer size")

    if idx >= end or view[idx] != 0x30:
        raise ValueError("SubjectPublicKeyInfo missing AlgorithmIdentifier")
    idx += 1
    algo_len, idx = _parse_der_length(view, idx)
    algo_end = idx + algo_len
    if algo_end > end:
        raise ValueError("AlgorithmIdentifier overruns SubjectPublicKeyInfo")

    algorithm_oid, value_idx = _decode_der_oid(view, idx)
    parameters: Optional[bytes] = None
    if value_idx < algo_end:
        parameters = bytes(view[value_idx:algo_end])

    return algorithm_oid, parameters


_ML_DSA_OID_TO_PARAMETER_SET: Dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


_ALGORITHM_OID_NAMES: Dict[str, str] = {
    oid: "ML-DSA" for oid in _ML_DSA_OID_TO_PARAMETER_SET
}


_ML_DSA_SIGNATURE_CONTEXT = b"FIDOSIG"
_ML_DSA_SIGNATURE_CONTEXT_LABEL = "FIDOSIG"
_ML_DSA_SIGNATURE_CONTEXT_ALIASES: Tuple[Tuple[str, bytes], ...] = (
    ("FIDOSIG", _ML_DSA_SIGNATURE_CONTEXT),
    ("FIDOSIG-PQC", b"FIDOSIG-PQC"),
    ("FIDOSIG-EXPERIMENTAL", b"FIDOSIG-EXPERIMENTAL"),
)


@dataclass(frozen=True)
class _MLDSAContextInvoker:
    """Callable that performs context-aware ML-DSA verification."""

    method_name: str
    callable: Callable[[bytes, bytes, Any, bytes], Any]
    context_value: Any
    context_label: Optional[str] = None


@dataclass
class _MLDSAFallbackAttempt:
    """Outcome of a fallback ML-DSA verification attempt."""

    label: str
    succeeded: Optional[bool]
    error: Optional[str]


@dataclass
class _MLDSAContextResult:
    """Metadata about context-aware ML-DSA verification attempts."""

    supported: bool
    attempted: bool
    succeeded: Optional[bool]
    error: Optional[str]
    method_name: Optional[str] = None
    errors: tuple[str, ...] = ()
    fallback_attempts: tuple[_MLDSAFallbackAttempt, ...] = ()

    @property
    def label(self) -> str:
        return _ML_DSA_SIGNATURE_CONTEXT_LABEL


_ML_DSA_PARAMETER_SET_DEFAULTS: Dict[str, Dict[str, Optional[int]]] = {
    "ML-DSA-44": {"public_key_length": 1312, "signature_length": 2420},
    "ML-DSA-65": {"public_key_length": 1952, "signature_length": 3293},
    "ML-DSA-87": {"public_key_length": 2592, "signature_length": 4595},
}


def _get_mldsa_parameter_details(parameter_set: Optional[str]) -> Dict[str, Optional[int]]:
    """Return expected ML-DSA parameter lengths, consulting oqs when available."""

    if not parameter_set:
        return {}

    details: Dict[str, Optional[int]] = dict(
        _ML_DSA_PARAMETER_SET_DEFAULTS.get(parameter_set, {})
    )

    oqs_module = _get_optional_oqs()
    if oqs_module is None:
        return details

    try:  # pragma: no cover - depends on optional oqs installation
        with oqs_module.Signature(parameter_set) as signature:
            signature_details = getattr(signature, "details", None)
    except BaseException:
        return details

    if isinstance(signature_details, Mapping):
        public_key_length = signature_details.get("length_public_key")
        signature_length = signature_details.get("length_signature")
        if public_key_length:
            details.setdefault("public_key_length", int(public_key_length))
        if signature_length:
            details.setdefault("signature_length", int(signature_length))

    return details


def _verify_mldsa_signature(
    verifier: Any,
    message: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    explicit_message_variants: Optional[Sequence[Tuple[str, bytes]]] = None,
    additional_messages: Sequence[Tuple[str, bytes]] = (),
    context_labels: Sequence[str] = (),
) -> tuple[bool, _MLDSAContextResult]:
    """Verify *signature* returning success flag and context attempt metadata."""

    def _iter_context_invokers() -> list[_MLDSAContextInvoker]:
        invokers: list[_MLDSAContextInvoker] = []

        seen_labels: Dict[str, bytes] = {}
        for label, value in _ML_DSA_SIGNATURE_CONTEXT_ALIASES:
            if label in seen_labels:
                continue
            seen_labels[label] = value
        for label in context_labels:
            if not isinstance(label, str):
                continue
            if label in seen_labels:
                continue
            seen_labels[label] = label.encode("utf-8")

        label_items = list(seen_labels.items())

        verify_with_ctx_str = getattr(verifier, "verify_with_ctx_str", None)
        if callable(verify_with_ctx_str):
            for label_str, value in label_items:
                invokers.append(
                    _MLDSAContextInvoker(
                        method_name="verify_with_ctx_str",
                        callable=verify_with_ctx_str,
                        context_value=label_str,
                        context_label=label_str,
                    )
                )

        verify_with_ctx = getattr(verifier, "verify_with_ctx", None)
        if callable(verify_with_ctx):
            for label_str, context_value in label_items:
                invokers.append(
                    _MLDSAContextInvoker(
                        method_name="verify_with_ctx",
                        callable=verify_with_ctx,
                        context_value=context_value,
                        context_label=label_str,
                    )
                )

        verify_with_ctx_bytes = getattr(verifier, "verify_with_ctx_bytes", None)
        if callable(verify_with_ctx_bytes):
            for label_str, context_value in label_items:
                invokers.append(
                    _MLDSAContextInvoker(
                        method_name="verify_with_ctx_bytes",
                        callable=verify_with_ctx_bytes,
                        context_value=context_value,
                        context_label=label_str,
                    )
                )

        return invokers

    context_invokers = _iter_context_invokers()
    context_supported = bool(context_invokers)
    context_attempted = False
    context_succeeded: Optional[bool] = None
    context_error_messages: list[str] = []
    context_error: Optional[str] = None
    selected_invoker: Optional[_MLDSAContextInvoker] = None
    primary_invoker: Optional[_MLDSAContextInvoker] = None

    fallback_attempts: list[_MLDSAFallbackAttempt] = []

    message_variants: list[tuple[str, bytes]] = []
    seen_messages: Set[bytes] = set()

    def _add_message_variant(label: str, payload: bytes) -> None:
        if payload in seen_messages:
            return
        message_variants.append((label, payload))
        seen_messages.add(payload)

    if explicit_message_variants:
        for label, payload in explicit_message_variants:
            if not isinstance(label, str):
                continue
            if not isinstance(payload, (bytes, bytearray, memoryview)):
                continue
            _add_message_variant(label, bytes(payload))
    else:
        _add_message_variant("original message", message)

    for label, payload in additional_messages:
        if not isinstance(label, str):
            continue
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            continue
        _add_message_variant(label, bytes(payload))

    rotation_block_lengths = (32, 48, 64)
    for block_length in rotation_block_lengths:
        if block_length >= len(message):
            continue

        leading = message[:block_length]
        trailing = message[block_length:]
        if trailing:
            rotated = trailing + leading
            _add_message_variant(
                f"{block_length}-byte leading block moved to end",
                rotated,
            )

        prefix = message[:-block_length]
        suffix = message[-block_length:]
        if prefix:
            shifted = suffix + prefix
            _add_message_variant(
                f"{block_length}-byte trailing block moved to front",
                shifted,
            )

    if context_supported:
        for invoker in context_invokers:
            context_attempted = True
            attempt_label = "context-aware verification"
            if invoker.context_label:
                attempt_label += f" using '{invoker.context_label}'"
            else:
                attempt_label += f" via {invoker.method_name}"
            try:
                context_result = bool(
                    invoker.callable(
                        message,
                        signature,
                        invoker.context_value,
                        public_key,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive path
                context_error_messages.append(f"{invoker.method_name}: {exc}")
                fallback_attempts.append(
                    _MLDSAFallbackAttempt(
                        label=attempt_label,
                        succeeded=None,
                        error=str(exc),
                    )
                )
                continue

            if primary_invoker is None:
                primary_invoker = invoker
            selected_invoker = invoker
            context_succeeded = context_result
            fallback_attempts.append(
                _MLDSAFallbackAttempt(
                    label=attempt_label,
                    succeeded=context_result,
                    error=None,
                )
            )
            if context_result:
                return True, _MLDSAContextResult(
                    supported=True,
                    attempted=True,
                    succeeded=True,
                    error=None,
                    method_name=invoker.method_name,
                    errors=tuple(context_error_messages),
                    fallback_attempts=tuple(fallback_attempts),
                )

    def _record_attempt(
        label: str,
        operation: Callable[[], bool],
    ) -> Optional[bool]:
        try:
            outcome = bool(operation())
        except Exception as exc:  # pragma: no cover - defensive path
            fallback_attempts.append(
                _MLDSAFallbackAttempt(label=label, succeeded=None, error=str(exc))
            )
            return None

        fallback_attempts.append(
            _MLDSAFallbackAttempt(label=label, succeeded=outcome, error=None)
        )
        return outcome

    digest_functions: tuple[tuple[str, Callable[[bytes], Any]], ...] = (
        ("SHA-256", hashlib.sha256),
        ("SHA-512", hashlib.sha512),
    )

    fallback_invoker = primary_invoker or selected_invoker

    if fallback_invoker is not None:
        for variant_label, variant_payload in message_variants[1:]:
            result = _record_attempt(
                f"context-aware verification using {variant_label}",
                lambda payload=variant_payload, invoker=fallback_invoker: invoker.callable(  # type: ignore[misc]
                    payload,
                    signature,
                    invoker.context_value,
                    public_key,
                ),
            )
            if result:
                return True, _MLDSAContextResult(
                    supported=context_supported,
                    attempted=True,
                    succeeded=context_succeeded,
                    error=context_error,
                    method_name=selected_invoker.method_name,
                    errors=tuple(context_error_messages),
                    fallback_attempts=tuple(fallback_attempts),
                )

        for base_label, base_payload in message_variants:
            for digest_name, digest_factory in digest_functions:
                digest = digest_factory(base_payload).digest()
                if digest == base_payload:
                    continue
                digest_label = f"{digest_name} digest of {base_label}"
                result = _record_attempt(
                    f"context-aware verification using {digest_label}",
                    lambda digest=digest, invoker=fallback_invoker: invoker.callable(  # type: ignore[misc]
                        digest,
                        signature,
                        invoker.context_value,
                        public_key,
                    ),
                )
                if result:
                    return True, _MLDSAContextResult(
                        supported=context_supported,
                        attempted=True,
                        succeeded=context_succeeded,
                        error=context_error,
                        method_name=selected_invoker.method_name,
                        errors=tuple(context_error_messages),
                        fallback_attempts=tuple(fallback_attempts),
                    )

    fallback_variants: list[tuple[str, bytes]] = []
    seen_variants: Set[bytes] = set()

    def _add_variant(label: str, payload: bytes) -> None:
        if payload in seen_variants:
            return
        fallback_variants.append((label, payload))
        seen_variants.add(payload)

    for base_label, base_payload in message_variants:
        _add_variant(base_label, base_payload)

    split_components = _split_webauthn_assertion_components(message)
    if split_components is not None:
        authenticator_bytes, client_hash_bytes, _ = split_components
        if client_hash_bytes and authenticator_bytes:
            _add_variant(
                "clientDataHash || authenticatorData",
                client_hash_bytes + authenticator_bytes,
            )
            _add_variant(
                "authenticatorData component only",
                authenticator_bytes,
            )
            _add_variant(
                "clientDataHash component only",
                client_hash_bytes,
            )

    if _ML_DSA_SIGNATURE_CONTEXT:
        context = bytes(_ML_DSA_SIGNATURE_CONTEXT)
        context_label = _ML_DSA_SIGNATURE_CONTEXT_LABEL

        for base_label, base_payload in message_variants:
            prefixed = context + base_payload
            if prefixed:
                _add_variant(
                    f"'{context_label}' prefix + {base_label}",
                    prefixed,
                )

            nul_prefixed = context + b"\x00" + base_payload
            if nul_prefixed:
                _add_variant(
                    f"'{context_label}' prefix + NUL separator + {base_label}",
                    nul_prefixed,
                )

    base_variants_snapshot = list(fallback_variants)
    for base_label, base_payload in base_variants_snapshot:
        for digest_name, digest_factory in digest_functions:
            digest = digest_factory(base_payload).digest()
            if digest == base_payload:
                continue
            digest_label = f"{digest_name} digest of {base_label}"
            _add_variant(digest_label, digest)

    for variant_label, candidate in fallback_variants:
        result = _record_attempt(
            f"context-free verification using {variant_label}",
            lambda candidate=candidate: verifier.verify(candidate, signature, public_key),
        )
        if result:
            return True, _MLDSAContextResult(
                supported=context_supported,
                attempted=context_attempted,
                succeeded=context_succeeded,
                error=context_error,
                method_name=selected_invoker.method_name if selected_invoker else None,
                errors=tuple(context_error_messages),
                fallback_attempts=tuple(fallback_attempts),
            )

    base_result = False
    if context_error_messages and selected_invoker is None and not context_succeeded:
        context_error = "; ".join(context_error_messages)

    return base_result, _MLDSAContextResult(
        supported=context_supported,
        attempted=context_attempted,
        succeeded=context_succeeded,
        error=context_error,
        method_name=selected_invoker.method_name if selected_invoker else None,
        errors=tuple(context_error_messages),
        fallback_attempts=tuple(fallback_attempts),
    )


def describe_mldsa_oid(oid: Optional[str]) -> Optional[Dict[str, str]]:
    """Return descriptive ML-DSA metadata for a certificate algorithm OID."""

    if not oid:
        return None

    parameter_set = _ML_DSA_OID_TO_PARAMETER_SET.get(oid)
    if parameter_set is None:
        return None

    return {
        "name": "ML-DSA",
        "mlDsaParameterSet": parameter_set,
        "display": parameter_set,
        "oid": oid,
    }


def describe_mldsa_oid_name(oid: Optional[str]) -> Optional[str]:
    """Return a user-friendly label for a recognised ML-DSA certificate OID."""

    details = describe_mldsa_oid(oid)
    if details is None:
        return None

    display = details.get("display")
    if isinstance(display, str) and display.strip():
        return display

    parameter_set = details.get("mlDsaParameterSet")
    if isinstance(parameter_set, str) and parameter_set.strip():
        return parameter_set

    name = details.get("name")
    if isinstance(name, str) and name.strip():
        return name

    return None


def _locate_subject_public_key_info_from_tbs(
    view: memoryview,
) -> tuple[bytes, str, Optional[bytes], bytes]:
    """Locate SubjectPublicKeyInfo by walking the TBSCertificate structure."""

    idx = 0
    if not view or view[idx] != 0x30:
        raise ValueError("Certificate must be a SEQUENCE")
    idx += 1
    cert_len, idx = _parse_der_length(view, idx)
    cert_end = idx + cert_len
    if cert_end > len(view):
        raise ValueError("Certificate length exceeds buffer size")

    if idx >= cert_end or view[idx] != 0x30:
        raise ValueError("Certificate missing TBSCertificate")
    idx += 1
    tbs_len, idx = _parse_der_length(view, idx)
    tbs_end = idx + tbs_len
    if tbs_end > cert_end:
        raise ValueError("TBSCertificate overruns Certificate")

    if idx < tbs_end and view[idx] == 0xA0:
        idx = _skip_der_value(view, idx)
    idx = _skip_der_value(view, idx)  # serialNumber
    idx = _skip_der_value(view, idx)  # signature
    idx = _skip_der_value(view, idx)  # issuer
    idx = _skip_der_value(view, idx)  # validity
    idx = _skip_der_value(view, idx)  # subject

    if idx >= tbs_end or view[idx] != 0x30:
        raise ValueError("TBSCertificate missing subjectPublicKeyInfo")
    spki_start = idx
    idx += 1
    spki_len, idx = _parse_der_length(view, idx)
    spki_end = idx + spki_len
    if spki_end > tbs_end:
        raise ValueError("subjectPublicKeyInfo overruns TBSCertificate")

    spki_der = bytes(view[spki_start:spki_end])
    algorithm_oid, algorithm_params = _parse_spki_algorithm_info(spki_der)
    subject_public_key = _extract_subject_public_key_from_spki(spki_der)
    return spki_der, algorithm_oid, algorithm_params, subject_public_key


def _scan_certificate_for_subject_public_key_info(
    view: memoryview,
) -> tuple[bytes, str, Optional[bytes], bytes]:
    """Search a DER-encoded certificate for a SubjectPublicKeyInfo structure."""

    length = len(view)
    for offset in range(length):
        if view[offset] != 0x30:
            continue
        try:
            seq_len, content_idx = _parse_der_length(view, offset + 1)
        except Exception:
            continue
        seq_end = content_idx + seq_len
        if seq_end > length or seq_len <= 0:
            continue

        inner_idx = content_idx
        if inner_idx >= seq_end or view[inner_idx] != 0x30:
            continue
        try:
            algo_len, algo_idx = _parse_der_length(view, inner_idx + 1)
        except Exception:
            continue
        algo_end = algo_idx + algo_len
        if algo_end > seq_end or algo_len <= 0:
            continue

        try:
            algorithm_oid, value_idx = _decode_der_oid(view, algo_idx)
        except Exception:
            continue

        parameters: Optional[bytes] = None
        if value_idx < algo_end:
            parameters = bytes(view[value_idx:algo_end])

        bitstring_idx = algo_end
        if bitstring_idx >= seq_end or view[bitstring_idx] != 0x03:
            continue
        try:
            bit_len, bit_content_idx = _parse_der_length(view, bitstring_idx + 1)
        except Exception:
            continue
        bit_end = bit_content_idx + bit_len
        if bit_end > seq_end or bit_len <= 0:
            continue

        unused_bits = view[bit_content_idx]
        if unused_bits != 0:
            continue
        payload = bytes(view[bit_content_idx + 1 : bit_end])
        if not payload:
            continue

        spki_der = bytes(view[offset:seq_end])
        return spki_der, algorithm_oid, parameters, payload

    raise ValueError("Unable to locate SubjectPublicKeyInfo in certificate")


def _extract_subject_public_key_info(
    cert_der: bytes,
) -> tuple[bytes, str, Optional[bytes], bytes]:
    """Return SubjectPublicKeyInfo components from *cert_der*."""

    view = memoryview(cert_der)
    try:
        return _locate_subject_public_key_info_from_tbs(view)
    except Exception as primary_error:
        try:
            return _scan_certificate_for_subject_public_key_info(view)
        except Exception:
            raise primary_error


def extract_certificate_public_key_info(cert_der: bytes) -> Dict[str, Any]:
    """Extract public key metadata from an X.509 certificate."""

    spki_der, algorithm_oid, algorithm_params, subject_public_key = (
        _extract_subject_public_key_info(cert_der)
    )
    wrapped_subject_public_key: Optional[bytes] = None

    info: Dict[str, Any] = {
        "algorithm_oid": algorithm_oid,
        "algorithm_parameters": algorithm_params,
        "subject_public_key_info": spki_der,
    }

    parameter_set = _ML_DSA_OID_TO_PARAMETER_SET.get(algorithm_oid)
    parameter_details: Dict[str, Optional[int]] = {}
    if parameter_set is not None:
        subject_public_key, wrapped_subject_public_key = _unwrap_mldsa_subject_public_key(
            subject_public_key, parameter_set
        )
        info["ml_dsa_parameter_set"] = parameter_set
        parameter_details = _get_mldsa_parameter_details(parameter_set)
        if parameter_details:
            info["ml_dsa_parameter_details"] = parameter_details
    algorithm_name = _ALGORITHM_OID_NAMES.get(algorithm_oid)
    if algorithm_name is not None:
        info["algorithm_name"] = algorithm_name
    display_name = describe_mldsa_oid_name(algorithm_oid)
    if display_name is not None:
        info["algorithm_display_name"] = display_name

    info["subject_public_key"] = subject_public_key
    if wrapped_subject_public_key is not None:
        info["wrapped_subject_public_key"] = wrapped_subject_public_key

    return info


def _coerce_mldsa_public_key_bytes(value: Any, parameter_set: Optional[str] = None) -> bytes:
    """Convert assorted public key representations into raw ML-DSA bytes."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        if data.startswith(b"\x30"):
            try:
                data = _extract_subject_public_key_from_spki(data)
            except Exception:
                pass
        normalized, _ = _unwrap_mldsa_subject_public_key(data, parameter_set)
        return normalized

    if isinstance(value, ByteBuffer):
        data = value.getvalue()
        normalized, _ = _unwrap_mldsa_subject_public_key(data, parameter_set)
        return normalized

    public_bytes = getattr(value, "public_bytes", None)
    if callable(public_bytes):  # pragma: no branch - exercised in tests
        attempts: Iterable[tuple[serialization.Encoding, serialization.PublicFormat]] = (
            (serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        for encoding, fmt in attempts:
            try:
                data = public_bytes(encoding, fmt)
            except Exception:
                continue
            if not data:
                continue
            if fmt is serialization.PublicFormat.SubjectPublicKeyInfo:
                try:
                    data = _extract_subject_public_key_from_spki(data)
                except Exception:
                    continue
            normalized, _ = _unwrap_mldsa_subject_public_key(bytes(data), parameter_set)
            return normalized

    raise TypeError("Unable to coerce ML-DSA public key into raw bytes")


def _as_bytes_or_none(value: Any) -> Optional[bytes]:
    """Return a ``bytes`` view of *value* when it is bytes-like."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    return None


def _split_webauthn_assertion_components(
    message_bytes: bytes,
) -> Optional[tuple[bytes, bytes, "AuthenticatorData"]]:
    """Attempt to split *message_bytes* into authenticatorData and clientDataHash."""

    if len(message_bytes) <= 32:
        return None

    authenticator_bytes = message_bytes[:-32]
    client_data_hash = message_bytes[-32:]
    if not authenticator_bytes:
        return None

    try:
        from .webauthn import AuthenticatorData  # local import to avoid cycle

        auth_data = AuthenticatorData(authenticator_bytes)
    except Exception:
        return None

    return authenticator_bytes, client_data_hash, auth_data


def _format_authenticator_data_summary(auth_data: "AuthenticatorData") -> str:
    """Return a compact summary string describing *auth_data*."""

    try:
        rp_id_hash_hex = auth_data.rp_id_hash.hex()
    except Exception:  # pragma: no cover - defensive
        rp_id_hash_hex = "unavailable"

    flag_value = int(auth_data.flags)
    flag_details: list[str] = []
    if getattr(auth_data, "is_user_present", None):
        flag_details.append(
            f"UP={'set' if auth_data.is_user_present() else 'clear'}"
        )
    if getattr(auth_data, "is_user_verified", None):
        flag_details.append(
            f"UV={'set' if auth_data.is_user_verified() else 'clear'}"
        )
    if getattr(auth_data, "is_backup_eligible", None):
        flag_details.append(
            f"BE={'set' if auth_data.is_backup_eligible() else 'clear'}"
        )
    if getattr(auth_data, "is_backup_state", None):
        flag_details.append(
            f"BS={'set' if auth_data.is_backup_state() else 'clear'}"
        )

    attested = "present" if auth_data.credential_data else "absent"
    extensions = "present" if auth_data.extensions else "absent"

    return (
        "rpIdHash="
        f"{rp_id_hash_hex}; flags=0x{flag_value:02x} ({', '.join(flag_details) or 'no-flags'})"
        f"; counter={auth_data.counter}; attested_credential_data={attested}; extensions={extensions}"
    )


def _analyze_mldsa_failure_factors(
    *,
    parameter_set: str,
    cose_key: "CoseKey",
    message_bytes: bytes,
    signature_bytes: bytes,
    public_key_bytes: bytes,
    context_result: Optional[_MLDSAContextResult],
) -> list[str]:
    """Return a factor-by-factor analysis for an ML-DSA verification failure."""

    analyses: list[str] = []

    # Factor A – Public key checks
    factor_a_bits: list[str] = []
    cose_raw_field = cose_key.get(-1)
    if cose_raw_field is None:
        factor_a_bits.append("COSE key missing -1 field; raw public key unavailable.")
    else:
        raw_bytes = _as_bytes_or_none(cose_raw_field)
        if raw_bytes is None:
            factor_a_bits.append(
                "COSE -1 field not bytes-like; unable to compare stored public key bytes."
            )
        else:
            raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            normalized_sha256 = hashlib.sha256(public_key_bytes).hexdigest()
            if raw_bytes == public_key_bytes:
                factor_a_bits.append(
                    "Canonicalized public key matches stored COSE bytes"
                    f" (sha256={normalized_sha256})."
                )
            else:
                factor_a_bits.append(
                    "Canonicalized public key differs from stored COSE bytes"
                    f" (raw_sha256={raw_sha256}, canonical_sha256={normalized_sha256})."
                )

    expected_lengths = _get_mldsa_parameter_details(parameter_set)
    key_length = expected_lengths.get("public_key_length")
    if key_length is not None:
        factor_a_bits.append(
            f"Public key length {len(public_key_bytes)} bytes; expected {key_length}."
        )
    else:
        factor_a_bits.append("Expected public key length unknown for parameter set.")

    analyses.append("Factor A (Public Key): " + " ".join(factor_a_bits))

    # Factor B – Message construction checks
    factor_b_bits: list[str] = [f"message_length={len(message_bytes)} bytes."]
    split_result = _split_webauthn_assertion_components(message_bytes)
    parsed_auth_data = None
    if split_result is not None:
        authenticator_bytes, client_hash, auth_data = split_result
        parsed_auth_data = auth_data
        factor_b_bits.append(
            "Parsed message as authenticatorData || clientDataHash: "
            f"authenticatorData_length={len(authenticator_bytes)}, clientDataHash_length={len(client_hash)}."
        )
        factor_b_bits.append(
            "AuthenticatorData summary: "
            + _format_authenticator_data_summary(auth_data)
        )
        factor_b_bits.append(
            "clientDataHash_sha256=" + hashlib.sha256(client_hash).hexdigest() + "."
        )
    else:
        factor_b_bits.append(
            "Unable to parse message into authenticatorData and clientDataHash;"
            " verify concatenation order and hashing logic."
        )

    if context_result is not None:
        relevant_attempts = [
            attempt
            for attempt in context_result.fallback_attempts
            if "clientData" in attempt.label or "authenticatorData" in attempt.label
        ]
        if relevant_attempts:
            attempt_bits = []
            for attempt in relevant_attempts:
                status = (
                    "succeeded"
                    if attempt.succeeded
                    else "failed"
                    if attempt.succeeded is False
                    else f"raised {attempt.error!r}"
                )
                attempt_bits.append(f"{attempt.label} {status}.")
            factor_b_bits.append("Message variant attempts: " + " ".join(attempt_bits))

    analyses.append("Factor B (Message): " + " ".join(factor_b_bits))

    # Factor C – Signature integrity checks
    factor_c_bits = [
        f"signature_type={'bytes' if isinstance(signature_bytes, bytes) else type(signature_bytes).__name__}",
        f"signature_length={len(signature_bytes)}",
        "signature_sha256=" + hashlib.sha256(signature_bytes).hexdigest() + ".",
    ]
    expected_signature_length = expected_lengths.get("signature_length")
    if expected_signature_length is not None:
        factor_c_bits.append(
            f"Expected signature length {expected_signature_length} bytes."
        )
    analyses.append("Factor C (Signature): " + " ".join(factor_c_bits))

    # Factor D – Algorithm / crypto alignment
    factor_d_bits: list[str] = []
    cose_alg = cose_key.get(3)
    factor_d_bits.append(f"COSE alg field={cose_alg!r} mapped to {parameter_set}.")
    if context_result is not None:
        if context_result.supported:
            if context_result.method_name:
                factor_d_bits.append(
                    f"oqs context method '{context_result.method_name}' was available."
                )
            if context_result.succeeded:
                factor_d_bits.append("Context-aware verification succeeded.")
            elif context_result.succeeded is False:
                factor_d_bits.append("Context-aware verification failed before fallback.")
            elif context_result.error:
                factor_d_bits.append(
                    f"Context-aware verification raised {context_result.error!r}."
                )
        else:
            factor_d_bits.append("oqs build lacked context-aware verification entry points.")
    analyses.append("Factor D (Algorithm/Crypto): " + " ".join(factor_d_bits))

    # Factor E – Transport / middleware observations
    factor_e_bits = [
        "Message and signature arrived as bytes at verification time;"
        " no additional JSON/base64 transformations detected in RP layer."
    ]
    analyses.append("Factor E (Transport/Middleware): " + " ".join(factor_e_bits))

    # Factor F – Authenticator behaviour insight
    factor_f_bits: list[str] = []
    if context_result is not None and context_result.fallback_attempts:
        total_attempts = len(context_result.fallback_attempts)
        successes = [a for a in context_result.fallback_attempts if a.succeeded]
        if not successes:
            factor_f_bits.append(
                "All RP-side fallback verifications failed; authenticator may have"
                " produced an invalid or non-standard ML-DSA signature."
            )
        else:
            factor_f_bits.append(
                f"{len(successes)} of {total_attempts} fallback attempts succeeded,"
                " indicating interoperable signature behaviour for some variants."
            )
    else:
        factor_f_bits.append(
            "No additional authenticator insight available beyond verification failure."
        )
    analyses.append("Factor F (Authenticator): " + " ".join(factor_f_bits))

    # Factor G – Replay and challenge checks
    factor_g_bits: list[str] = []
    if parsed_auth_data is not None:
        present_state = (
            parsed_auth_data.is_user_present()
            if hasattr(parsed_auth_data, "is_user_present")
            else "unknown"
        )
        verified_state = (
            parsed_auth_data.is_user_verified()
            if hasattr(parsed_auth_data, "is_user_verified")
            else "unknown"
        )
        factor_g_bits.append(
            "AuthenticatorData counter="
            f"{parsed_auth_data.counter}; user_present={present_state}; user_verified={verified_state}."
        )
    factor_g_bits.append(
        "Challenge, origin, and RP ID validations occur before signature verification"
        " in the server flow, reducing replay risk."
    )
    analyses.append("Factor G (Replay/Security): " + " ".join(factor_g_bits))

    return analyses


def _describe_mldsa_signature_verification_failure(
    *,
    parameter_set: str,
    cose_key: "CoseKey",
    message: Any,
    message_bytes: bytes,
    signature: Any,
    signature_bytes: bytes,
    public_key: Any,
    public_key_bytes: bytes,
    context_result: Optional[_MLDSAContextResult] = None,
    diagnostic_json: Optional[str] = None,
) -> list[str]:
    """Return diagnostic strings for an ML-DSA verification failure."""

    def _safe_len(value: Any) -> Optional[int]:
        try:
            return len(value)  # type: ignore[arg-type]
        except Exception:
            return None

    def _describe_bytes_origin(original: Any, coerced: bytes) -> str:
        if isinstance(original, (bytes, bytearray, memoryview)):
            return "shared" if original is coerced else "copied"
        if isinstance(original, ByteBuffer):
            return "ByteBuffer"
        return "coerced"

    def _maybe_sha256(data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return digest

    parts: list[str] = []
    parts.append(
        "oqs verifier reported an invalid ML-DSA signature."
        f" Parameter set in use: {parameter_set}."
    )

    cose_fields = sorted(cose_key.keys())
    parts.append(
        "COSE key summary: class="
        f"{type(cose_key).__name__}, fields={list(cose_fields)}, type_field={cose_key.get(1)!r}, "
        f"alg_field={cose_key.get(3)!r}."
    )

    if -1 in cose_key:
        raw_public_key = cose_key.get(-1)
        raw_public_key_length = _safe_len(raw_public_key)
        raw_length_msg = (
            f"length={raw_public_key_length}"
            if raw_public_key_length is not None
            else "length=unknown"
        )
        parts.append(
            "COSE raw public key field present: type="
            f"{type(raw_public_key).__name__}, {raw_length_msg}."
        )
    else:
        parts.append("COSE raw public key field missing (-1 not present).")

    message_original_length = _safe_len(message)
    message_original_length_msg = (
        f"original_length={message_original_length}"
        if message_original_length is not None
        else "original_length=unknown"
    )
    parts.append(
        "Message details: type="
        f"{type(message).__name__}, {message_original_length_msg}, coerced_length={len(message_bytes)}, "
        f"bytes_origin={_describe_bytes_origin(message, message_bytes)}, sha256={_maybe_sha256(message_bytes)}, "
        f"bytes_like={isinstance(message, (bytes, bytearray, memoryview))}."
    )

    signature_original_length = _safe_len(signature)
    signature_original_length_msg = (
        f"original_length={signature_original_length}"
        if signature_original_length is not None
        else "original_length=unknown"
    )
    signature_length = len(signature_bytes)
    parts.append(
        "Signature details: type="
        f"{type(signature).__name__}, {signature_original_length_msg}, coerced_length={signature_length}, "
        f"bytes_origin={_describe_bytes_origin(signature, signature_bytes)}, sha256={_maybe_sha256(signature_bytes)}, "
        f"bytes_like={isinstance(signature, (bytes, bytearray, memoryview))}."
    )

    public_key_original_length = _safe_len(public_key)
    public_key_original_length_msg = (
        f"original_length={public_key_original_length}"
        if public_key_original_length is not None
        else "original_length=unknown"
    )
    public_key_length = len(public_key_bytes)
    parts.append(
        "Verifier public key details: type="
        f"{type(public_key).__name__}, {public_key_original_length_msg}, coerced_length={public_key_length}, "
        f"bytes_origin={_describe_bytes_origin(public_key, public_key_bytes)}, sha256={_maybe_sha256(public_key_bytes)}, "
        f"bytes_like={isinstance(public_key, (bytes, bytearray, memoryview))}."
    )

    if context_result is not None:
        if not context_result.supported:
            parts.append(
                "oqs bindings do not expose a context-aware verifier; ML-DSA "
                "context support unavailable."
            )
        elif context_result.attempted:
            method_suffix = (
                f" via {context_result.method_name}" if context_result.method_name else ""
            )
            if context_result.succeeded is True:
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}'{method_suffix} succeeded."
                )
            elif context_result.succeeded is False:
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}'{method_suffix} failed; falling back to "
                    "context-free verification."
                )
            else:
                error_detail = context_result.error
                if error_detail is None and context_result.errors:
                    error_detail = "; ".join(context_result.errors)
                if error_detail is None:
                    error_detail = "unknown error"
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}'{method_suffix} raised "
                    f"{error_detail!r}; falling back to context-free verification."
                )
        else:
            parts.append(
                "A context-aware ML-DSA verifier was exposed but no attempt was made."
            )

        for error_msg in context_result.errors:
            parts.append(f"Context-aware verifier {error_msg}.")

        for attempt in context_result.fallback_attempts:
            if attempt.error is not None:
                parts.append(
                    f"Fallback {attempt.label} raised {attempt.error!r}."
                )
            elif attempt.succeeded:
                parts.append(f"Fallback {attempt.label} succeeded.")
            else:
                parts.append(f"Fallback {attempt.label} failed.")

    parameter_details = _get_mldsa_parameter_details(parameter_set)
    expected_signature_length = parameter_details.get("signature_length")
    if expected_signature_length is not None:
        if signature_length != expected_signature_length:
            parts.append(
                "Signature length mismatch: "
                f"expected {expected_signature_length}, observed {signature_length}."
            )
        else:
            parts.append(
                "Signature length matches expected "
                f"{expected_signature_length}."
            )
    else:
        parts.append("Signature expected length unknown for this parameter set.")

    expected_public_key_length = parameter_details.get("public_key_length")
    if expected_public_key_length is not None:
        if public_key_length != expected_public_key_length:
            parts.append(
                "Public key length mismatch: "
                f"expected {expected_public_key_length}, observed {public_key_length}."
            )
        else:
            parts.append(
                "Public key length matches expected "
                f"{expected_public_key_length}."
            )
    else:
        parts.append("Public key expected length unknown for this parameter set.")

    parts.extend(
        _analyze_mldsa_failure_factors(
            parameter_set=parameter_set,
            cose_key=cose_key,
            message_bytes=message_bytes,
            signature_bytes=signature_bytes,
            public_key_bytes=public_key_bytes,
            context_result=context_result,
        )
    )

    if diagnostic_json is not None:
        parts.append(diagnostic_json)

    return parts


class CoseKey(dict):
    """A COSE formatted public key.

    :param _: The COSE key paramters.
    :cvar ALGORITHM: COSE algorithm identifier.
    """

    ALGORITHM: int = None  # type: ignore

    def verify(self, message: bytes, signature: bytes) -> None:
        """Validates a digital signature over a given message.

        :param message: The message which was signed.
        :param signature: The signature to check.
        """
        raise NotImplementedError("Signature verification not supported.")

    @classmethod
    def from_cryptography_key(
        cls: Type[T_CoseKey], public_key: types.PublicKeyTypes
    ) -> T_CoseKey:
        """Converts a PublicKey object from Cryptography into a COSE key.

        :param public_key: Either an EC or RSA public key.
        :return: A CoseKey.
        """
        raise NotImplementedError("Creation from cryptography not supported.")

    @staticmethod
    def for_alg(alg: int) -> Type[CoseKey]:
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """
        for cls in CoseKey.__subclasses__():
            if cls.ALGORITHM == alg:
                return cls
        return UnsupportedKey

    @staticmethod
    def for_name(name: str) -> Type[CoseKey]:
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """
        for cls in CoseKey.__subclasses__():
            if cls.__name__ == name:
                return cls
        return UnsupportedKey

    @staticmethod
    def parse(cose: Mapping[int, Any]) -> CoseKey:
        """Create a CoseKey from a dict"""
        alg = cose.get(3)
        if not alg:
            raise ValueError("COSE alg identifier must be provided.")
        return CoseKey.for_alg(alg)(cose)

    @staticmethod
    def supported_algorithms() -> Sequence[int]:
        """Get a list of all supported algorithm identifiers"""
        algs: Sequence[Type[CoseKey]] = [
            MLDSA44,
            MLDSA65,
            MLDSA87,
            ES256,
            EdDSA,
            ES384,
            ES512,
            ES256K,
            PS256,
            PS384,
            PS512,
            RS256,
            RS384,
            RS512,
            RS1,
        ]
        return [cls.ALGORITHM for cls in algs]


T_CoseKey = TypeVar("T_CoseKey", bound=CoseKey)


class UnsupportedKey(CoseKey):
    """A COSE key with an unsupported algorithm."""


class MLDSA87(CoseKey):
    ALGORITHM = -50
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[1] != 7:
            raise ValueError("Unsupported ML-DSA-87 Param")
        oqs_module = _require_oqs()
        public_key = self.get(-1)
        if public_key is None:
            raise ValueError("Missing ML-DSA-87 public key")
        message_bytes = (
            message
            if isinstance(message, (bytes, bytearray, memoryview))
            else bytes(message)
        )
        signature_bytes = (
            signature
            if isinstance(signature, (bytes, bytearray, memoryview))
            else bytes(signature)
        )
        message_bytes = bytes(message_bytes)
        signature_bytes = bytes(signature_bytes)
        parameter_set = "ML-DSA-87"
        public_key_bytes = _coerce_mldsa_public_key_bytes(public_key, parameter_set)
        public_key_bytes = bytes(public_key_bytes)
        with oqs_module.Signature(parameter_set) as verifier:
            verified, context_result = _verify_mldsa_signature(
                verifier,
                message_bytes,
                signature_bytes,
                public_key_bytes,
            )
        if not verified:
            error_messages = _describe_mldsa_signature_verification_failure(
                parameter_set=parameter_set,
                cose_key=self,
                message=message,
                message_bytes=message_bytes,
                signature=signature,
                signature_bytes=signature_bytes,
                public_key=public_key,
                public_key_bytes=public_key_bytes,
                context_result=context_result,
            )
            raise ValueError("; ".join(error_messages))

    @classmethod
    def from_cryptography_key(cls, public_key):
        return cls(
            {
                1: 7,
                3: cls.ALGORITHM,
                -1: _coerce_mldsa_public_key_bytes(public_key, "ML-DSA-87"),
            }
        )


class MLDSA65(CoseKey):
    ALGORITHM = -49
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[1] != 7:
            raise ValueError("Unsupported ML-DSA-65 Param")
        oqs_module = _require_oqs()
        public_key = self.get(-1)
        if public_key is None:
            raise ValueError("Missing ML-DSA-65 public key")
        message_bytes = (
            message
            if isinstance(message, (bytes, bytearray, memoryview))
            else bytes(message)
        )
        signature_bytes = (
            signature
            if isinstance(signature, (bytes, bytearray, memoryview))
            else bytes(signature)
        )
        message_bytes = bytes(message_bytes)
        signature_bytes = bytes(signature_bytes)
        parameter_set = "ML-DSA-65"
        public_key_bytes = _coerce_mldsa_public_key_bytes(public_key, parameter_set)
        public_key_bytes = bytes(public_key_bytes)
        with oqs_module.Signature(parameter_set) as verifier:
            verified, context_result = _verify_mldsa_signature(
                verifier,
                message_bytes,
                signature_bytes,
                public_key_bytes,
            )
        if not verified:
            error_messages = _describe_mldsa_signature_verification_failure(
                parameter_set=parameter_set,
                cose_key=self,
                message=message,
                message_bytes=message_bytes,
                signature=signature,
                signature_bytes=signature_bytes,
                public_key=public_key,
                public_key_bytes=public_key_bytes,
                context_result=context_result,
            )
            raise ValueError("; ".join(error_messages))

    @classmethod
    def from_cryptography_key(cls, public_key):
        return cls(
            {
                1: 7,
                3: cls.ALGORITHM,
                -1: _coerce_mldsa_public_key_bytes(public_key, "ML-DSA-65"),
            }
        )

class MLDSA44(CoseKey):
    ALGORITHM = -48
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[1] != 7:
            raise ValueError("Unsupported ML-DSA-44 Param")
        oqs_module = _require_oqs()
        public_key = self.get(-1)
        if public_key is None:
            raise ValueError("Missing ML-DSA-44 public key")
        parameter_set = "ML-DSA-44"

        context_info = getattr(self, "_mldsa44_context", None)
        if hasattr(self, "_mldsa44_context"):
            delattr(self, "_mldsa44_context")
        if context_info is None:
            context_info = {}
        else:
            context_info = dict(context_info)

        def _as_bytes(value: Any) -> bytes:
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            if isinstance(value, ByteBuffer):
                return value.getvalue()
            if isinstance(value, str):
                return value.encode("utf-8")
            return bytes(value)

        message_bytes = _as_bytes(message)
        signature_bytes = _as_bytes(signature)
        public_key_bytes = bytes(
            _coerce_mldsa_public_key_bytes(public_key, parameter_set)
        )

        parameter_details = _get_mldsa_parameter_details(parameter_set)
        expected_signature_length = parameter_details.get("signature_length")
        expected_public_key_length = parameter_details.get("public_key_length")

        message_variants: List[Dict[str, Any]] = []
        message_seen: Set[bytes] = set()

        def _add_message_variant(label: str, payload: bytes) -> None:
            if payload in message_seen:
                return
            message_seen.add(payload)
            message_variants.append(
                {
                    "label": label,
                    "bytes": payload,
                    "length": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )

        _add_message_variant("provided_message", message_bytes)

        authenticator_bytes: Optional[bytes] = None
        client_hash_bytes: Optional[bytes] = None
        auth_data_summary: Optional[str] = None

        split_components = _split_webauthn_assertion_components(message_bytes)
        if split_components is not None:
            authenticator_bytes, client_hash_bytes, auth_data = split_components
            spec_default = authenticator_bytes + client_hash_bytes
            _add_message_variant(
                "authenticatorData||clientDataHash (spec_default)",
                spec_default,
            )
            _add_message_variant("authenticatorData_only", authenticator_bytes)
            _add_message_variant("clientDataHash_only", client_hash_bytes)
            _add_message_variant(
                "SHA256(authenticatorData||clientDataHash)",
                hashlib.sha256(spec_default).digest(),
            )
            auth_data_summary = _format_authenticator_data_summary(auth_data)

        client_data_json = context_info.get("client_data_json")
        if isinstance(client_data_json, ByteBuffer):
            client_data_json = client_data_json.getvalue()
        if isinstance(client_data_json, (bytes, bytearray, memoryview)):
            client_json_bytes = bytes(client_data_json)
            _add_message_variant("clientDataJSON_raw", client_json_bytes)
            _add_message_variant(
                "SHA256(clientDataJSON)",
                hashlib.sha256(client_json_bytes).digest(),
            )

        signature_variants: List[Dict[str, Any]] = []
        signature_seen: Set[bytes] = set()

        def _add_signature_variant(
            label: str, payload: bytes, *, error: Optional[str] = None
        ) -> None:
            normalized = bytes(payload)
            valid_length = True
            variant_error = error
            if expected_signature_length is not None and len(normalized) != expected_signature_length:
                valid_length = False
                if variant_error is None:
                    variant_error = (
                        f"length {len(normalized)} != expected "
                        f"{expected_signature_length}"
                    )
            signature_variants.append(
                {
                    "label": label,
                    "bytes": normalized,
                    "length": len(normalized),
                    "sha256": hashlib.sha256(normalized).hexdigest(),
                    "valid_length": valid_length and variant_error is None,
                    "error": variant_error,
                }
            )
            signature_seen.add(normalized)

        _add_signature_variant("provided_signature", signature_bytes)

        signature_text_candidates: List[str] = []
        if isinstance(signature, str):
            signature_text_candidates.append(signature)
        else:
            try:
                signature_text = signature_bytes.decode("ascii")
            except Exception:
                signature_text = None
            if signature_text:
                signature_text_candidates.append(signature_text)

        def _decode_with_padding(value: str, *, urlsafe: bool) -> bytes:
            normalized = value.strip()
            padding = "=" * ((4 - len(normalized) % 4) % 4)
            data = normalized + padding
            if urlsafe:
                return base64.urlsafe_b64decode(data)
            return base64.b64decode(data)

        for idx, text in enumerate(signature_text_candidates):
            prefix = f"candidate{idx}"
            try:
                decoded_url = _decode_with_padding(text, urlsafe=True)
            except Exception as exc:
                signature_variants.append(
                    {
                        "label": f"{prefix}_base64url-decoded",
                        "bytes": b"",
                        "length": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "valid_length": False,
                        "error": f"decode error: {exc}",
                    }
                )
            else:
                if decoded_url not in signature_seen:
                    _add_signature_variant(
                        f"{prefix}_base64url-decoded",
                        decoded_url,
                    )
            try:
                decoded_std = _decode_with_padding(text, urlsafe=False)
            except Exception as exc:
                signature_variants.append(
                    {
                        "label": f"{prefix}_base64-decoded",
                        "bytes": b"",
                        "length": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "valid_length": False,
                        "error": f"decode error: {exc}",
                    }
                )
            else:
                if decoded_std not in signature_seen:
                    _add_signature_variant(
                        f"{prefix}_base64-decoded",
                        decoded_std,
                    )

        public_keys: List[Dict[str, Any]] = []
        public_key_seen: Set[bytes] = set()

        def _add_public_key(label: str, payload: bytes) -> None:
            normalized = bytes(payload)
            if normalized in public_key_seen:
                return
            public_key_seen.add(normalized)
            expected_length = expected_public_key_length
            matches_expected = (
                expected_length is None or len(normalized) == expected_length
            )
            public_keys.append(
                {
                    "label": label,
                    "bytes": normalized,
                    "length": len(normalized),
                    "sha256": hashlib.sha256(normalized).hexdigest(),
                    "matches_expected_length": matches_expected,
                    "expected_length": expected_length,
                }
            )

        _add_public_key(context_info.get("primary_public_key_label", "COSE -1 field"), public_key_bytes)

        alternate_public_keys = context_info.get("alternate_public_keys")
        if isinstance(alternate_public_keys, (list, tuple)):
            for entry in alternate_public_keys:
                if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                    continue
                label, value = entry
                try:
                    alternate_bytes = _coerce_mldsa_public_key_bytes(value, parameter_set)
                except Exception:
                    continue
                _add_public_key(str(label), alternate_bytes)

        message_variant_tuples = [
            (variant["label"], variant["bytes"]) for variant in message_variants
        ]

        if not message_variant_tuples:
            message_variant_tuples = [("provided_message", message_bytes)]

        context_labels = []
        context_label_values = context_info.get("context_labels")
        if isinstance(context_label_values, (list, tuple)):
            context_labels = [str(label) for label in context_label_values if isinstance(label, str)]

        parameter_sets_to_try = context_info.get("parameter_sets")
        if isinstance(parameter_sets_to_try, (list, tuple)) and parameter_sets_to_try:
            parameter_order = [str(p) for p in parameter_sets_to_try]
        else:
            parameter_order = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

        attempts: List[Dict[str, Any]] = []
        primary_context_result: Optional[_MLDSAContextResult] = None
        verification_succeeded = False

        def _fallbacks_to_dict(
            result: _MLDSAContextResult,
        ) -> List[Dict[str, Optional[str]]]:
            items: List[Dict[str, Optional[str]]] = []
            for attempt in result.fallback_attempts:
                items.append(
                    {
                        "label": attempt.label,
                        "succeeded": attempt.succeeded,
                        "error": attempt.error,
                    }
                )
            return items

        for parameter_option in parameter_order:
            try:
                signature_impl = oqs_module.Signature(parameter_option)
            except Exception as exc:
                attempts.append(
                    {
                        "variant": f"param={parameter_option}|init",
                        "parameter_set": parameter_option,
                        "result": False,
                        "error": f"verifier init failed: {exc}",
                    }
                )
                continue

            parameter_expected = _get_mldsa_parameter_details(parameter_option).get(
                "public_key_length"
            )

            with signature_impl as verifier:
                for key_index, key_entry in enumerate(public_keys):
                    key_bytes_candidate = key_entry["bytes"]
                    key_label = key_entry["label"]
                    key_matches = (
                        parameter_expected is None
                        or len(key_bytes_candidate) == parameter_expected
                    )
                    for sig_index, signature_entry in enumerate(signature_variants):
                        if signature_entry.get("error"):
                            attempts.append(
                                {
                                    "variant": (
                                        f"param={parameter_option}|key={key_label}|"
                                        f"signature={signature_entry['label']}"
                                    ),
                                    "parameter_set": parameter_option,
                                    "public_key": key_label,
                                    "signature_variant": signature_entry["label"],
                                    "result": False,
                                    "error": signature_entry["error"],
                                }
                            )
                            continue
                        if not signature_entry.get("valid_length", True):
                            attempts.append(
                                {
                                    "variant": (
                                        f"param={parameter_option}|key={key_label}|"
                                        f"signature={signature_entry['label']}"
                                    ),
                                    "parameter_set": parameter_option,
                                    "public_key": key_label,
                                    "signature_variant": signature_entry["label"],
                                    "result": False,
                                    "error": "signature length invalid",
                                }
                            )
                            continue

                        try:
                            verified, context_result = _verify_mldsa_signature(
                                verifier,
                                message_variant_tuples[0][1],
                                signature_entry["bytes"],
                                key_bytes_candidate,
                                explicit_message_variants=message_variant_tuples,
                                context_labels=context_labels,
                            )
                        except Exception as exc:
                            attempts.append(
                                {
                                    "variant": (
                                        f"param={parameter_option}|key={key_label}|"
                                        f"signature={signature_entry['label']}"
                                    ),
                                    "parameter_set": parameter_option,
                                    "public_key": key_label,
                                    "signature_variant": signature_entry["label"],
                                    "result": False,
                                    "error": str(exc),
                                }
                            )
                            continue

                        attempt_record = {
                            "variant": (
                                f"param={parameter_option}|key={key_label}|"
                                f"signature={signature_entry['label']}"
                            ),
                            "parameter_set": parameter_option,
                            "public_key": key_label,
                            "public_key_length": len(key_bytes_candidate),
                            "public_key_matches_expected": key_matches,
                            "signature_variant": signature_entry["label"],
                            "signature_length": len(signature_entry["bytes"]),
                            "signature_sha256": signature_entry["sha256"],
                            "message_variants": [
                                variant["label"] for variant in message_variants
                            ],
                            "context_supported": context_result.supported,
                            "context_attempted": context_result.attempted,
                            "context_method": context_result.method_name,
                            "context_errors": list(context_result.errors),
                            "fallback_attempts": _fallbacks_to_dict(context_result),
                            "result": bool(verified),
                        }
                        attempts.append(attempt_record)

                        if (
                            primary_context_result is None
                            and parameter_option == parameter_set
                            and key_index == 0
                            and sig_index == 0
                        ):
                            primary_context_result = context_result

                        if verified:
                            verification_succeeded = True
                            break
                    if verification_succeeded:
                        break
                if verification_succeeded:
                    break

            if verification_succeeded:
                break

        if verification_succeeded:
            return

        def _first_hex(data: bytes) -> str:
            return data[:32].hex()

        def _last_hex(data: bytes) -> str:
            return data[-32:].hex() if len(data) >= 32 else data.hex()

        diagnostic_payload = {
            "success": False,
            "verified": False,
            "ceremony": context_info.get("ceremony", "unknown"),
            "challenge_sha256": context_info.get("challenge_sha256", "unavailable"),
            "rpIdHash": (
                context_info.get("rp_id_hash")
                or (authenticator_bytes[:32].hex() if authenticator_bytes else None)
            ),
            "clientDataHash_hex": client_hash_bytes.hex()
            if client_hash_bytes
            else None,
            "message_sha256": hashlib.sha256(message_bytes).hexdigest(),
            "message_length": len(message_bytes),
            "message_prefix32_hex": _first_hex(message_bytes),
            "message_suffix32_hex": _last_hex(message_bytes),
            "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
            "signature_length": len(signature_bytes),
            "signature_prefix32_hex": _first_hex(signature_bytes),
            "signature_suffix32_hex": _last_hex(signature_bytes),
            "publicKey_sha256": hashlib.sha256(public_key_bytes).hexdigest(),
            "publicKey_length": len(public_key_bytes),
            "publicKey_matches_expected_length": (
                expected_public_key_length is None
                or len(public_key_bytes) == expected_public_key_length
            ),
            "message_variants": [
                {
                    "label": variant["label"],
                    "length": variant["length"],
                    "sha256": variant["sha256"],
                }
                for variant in message_variants
            ],
            "signature_variants": [
                {
                    "label": variant["label"],
                    "length": variant["length"],
                    "sha256": variant["sha256"],
                    "valid_length": variant["valid_length"],
                    "error": variant.get("error"),
                }
                for variant in signature_variants
            ],
            "public_keys": [
                {
                    "label": entry["label"],
                    "length": entry["length"],
                    "sha256": entry["sha256"],
                    "matches_expected_length": entry["matches_expected_length"],
                    "expected_length": entry["expected_length"],
                }
                for entry in public_keys
            ],
            "attempts": attempts,
            "authenticator_data_summary": auth_data_summary,
            "conclusion": "Likely authenticator-side issue if all failed.",
        }

        diagnostic_json = json.dumps(diagnostic_payload, sort_keys=True)

        error_messages = _describe_mldsa_signature_verification_failure(
            parameter_set=parameter_set,
            cose_key=self,
            message=message,
            message_bytes=message_bytes,
            signature=signature,
            signature_bytes=signature_bytes,
            public_key=public_key,
            public_key_bytes=public_key_bytes,
            context_result=primary_context_result,
            diagnostic_json=diagnostic_json,
        )
        raise ValueError("; ".join(error_messages))

    @classmethod
    def from_cryptography_key(cls, public_key):
        return cls(
            {
                1: 7,
                3: cls.ALGORITHM,
                -1: _coerce_mldsa_public_key_bytes(public_key, "ML-DSA-44"),
            }
        )

class ES256(CoseKey):
    ALGORITHM = -7
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[-1] != 1:
            raise ValueError("Unsupported elliptic curve")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP256R1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(self._HASH_ALG)
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, ec.EllipticCurvePublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls(
            {
                1: 2,
                3: cls.ALGORITHM,
                -1: 1,
                -2: int2bytes(pn.x, 32),
                -3: int2bytes(pn.y, 32),
            }
        )

    @classmethod
    def from_ctap1(cls, data):
        """Creates an ES256 key from a CTAP1 formatted public key byte string.

        :param data: A 65 byte SECP256R1 public key.
        :return: A ES256 key.
        """
        return cls({1: 2, 3: cls.ALGORITHM, -1: 1, -2: data[1:33], -3: data[33:65]})


class ES384(CoseKey):
    ALGORITHM = -35
    _HASH_ALG = hashes.SHA384()

    def verify(self, message, signature):
        if self[-1] != 2:
            raise ValueError("Unsupported elliptic curve")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP384R1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(self._HASH_ALG)
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, ec.EllipticCurvePublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls(
            {
                1: 2,
                3: cls.ALGORITHM,
                -1: 2,
                -2: int2bytes(pn.x, 48),
                -3: int2bytes(pn.y, 48),
            }
        )


class ES512(CoseKey):
    ALGORITHM = -36
    _HASH_ALG = hashes.SHA512()

    def verify(self, message, signature):
        if self[-1] != 3:
            raise ValueError("Unsupported elliptic curve")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP521R1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(self._HASH_ALG)
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, ec.EllipticCurvePublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls(
            {
                1: 2,
                3: cls.ALGORITHM,
                -1: 3,
                -2: int2bytes(pn.x, 66),
                -3: int2bytes(pn.y, 66),
            }
        )


class RS256(CoseKey):
    ALGORITHM = -257
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class RS384(CoseKey):
    ALGORITHM = -258
    _HASH_ALG = hashes.SHA384()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class RS512(CoseKey):
    ALGORITHM = -259
    _HASH_ALG = hashes.SHA512()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class PS256(CoseKey):
    ALGORITHM = -37
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(self._HASH_ALG), salt_length=padding.PSS.MAX_LENGTH
            ),
            self._HASH_ALG,
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class PS384(CoseKey):
    ALGORITHM = -38
    _HASH_ALG = hashes.SHA384()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(self._HASH_ALG), salt_length=padding.PSS.MAX_LENGTH
            ),
            self._HASH_ALG,
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class PS512(CoseKey):
    ALGORITHM = -39
    _HASH_ALG = hashes.SHA512()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(self._HASH_ALG), salt_length=padding.PSS.MAX_LENGTH
            ),
            self._HASH_ALG,
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class EdDSA(CoseKey):
    ALGORITHM = -8

    def verify(self, message, signature):
        if self[-1] != 6:
            raise ValueError("Unsupported elliptic curve")
        ed25519.Ed25519PublicKey.from_public_bytes(self[-2]).verify(signature, message)

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, ed25519.Ed25519PublicKey)  # nosec
        return cls(
            {
                1: 1,
                3: cls.ALGORITHM,
                -1: 6,
                -2: public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
            }
        )


class RS1(CoseKey):
    ALGORITHM = -65535
    _HASH_ALG = hashes.SHA1()  # nosec

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, rsa.RSAPublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class ES256K(CoseKey):
    ALGORITHM = -47
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[-1] != 8:
            raise ValueError("Unsupported elliptic curve")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP256K1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(self._HASH_ALG)
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        assert isinstance(public_key, ec.EllipticCurvePublicKey)  # nosec
        pn = public_key.public_numbers()
        return cls(
            {
                1: 2,
                3: cls.ALGORITHM,
                -1: 8,
                -2: int2bytes(pn.x, 32),
                -3: int2bytes(pn.y, 32),
            }
        )
