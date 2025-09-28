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

import hashlib

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
) -> tuple[bool, _MLDSAContextResult]:
    """Verify *signature* returning success flag and context attempt metadata."""

    verify_with_ctx = getattr(verifier, "verify_with_ctx_str", None)
    context_supported = callable(verify_with_ctx)
    context_attempted = False
    context_succeeded: Optional[bool] = None
    context_error: Optional[str] = None

    fallback_attempts: list[_MLDSAFallbackAttempt] = []

    if context_supported and _ML_DSA_SIGNATURE_CONTEXT:
        context_attempted = True
        try:
            context_result = bool(
                verify_with_ctx(  # type: ignore[misc]
                    message,
                    signature,
                    _ML_DSA_SIGNATURE_CONTEXT,
                    public_key,
                )
            )
        except Exception as exc:  # pragma: no cover - defensive path
            context_error = str(exc)
        else:
            context_succeeded = context_result
            if context_result:
                return True, _MLDSAContextResult(
                    supported=True,
                    attempted=True,
                    succeeded=True,
                    error=None,
                    fallback_attempts=(),
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

    digest_variants: list[tuple[str, bytes]] = []
    digest_functions: tuple[tuple[str, Callable[[bytes], Any]], ...] = (
        ("SHA-256", hashlib.sha256),
        ("SHA-512", hashlib.sha512),
    )

    for digest_name, digest_factory in digest_functions:
        digest = digest_factory(message).digest()
        if digest != message:
            digest_variants.append((f"{digest_name} digest of original message", digest))

    if context_supported and _ML_DSA_SIGNATURE_CONTEXT:
        for digest_label, digest in digest_variants:
            result = _record_attempt(
                f"context-aware verification using {digest_label}",
                lambda digest=digest: verify_with_ctx(  # type: ignore[misc]
                    digest,
                    signature,
                    _ML_DSA_SIGNATURE_CONTEXT,
                    public_key,
                ),
            )
            if result:
                return True, _MLDSAContextResult(
                    supported=context_supported,
                    attempted=True,
                    succeeded=context_succeeded,
                    error=context_error,
                    fallback_attempts=tuple(fallback_attempts),
                )

    fallback_variants: list[tuple[str, bytes]] = []
    seen_variants: Set[bytes] = set()

    def _add_variant(label: str, payload: bytes) -> None:
        if payload in seen_variants:
            return
        fallback_variants.append((label, payload))
        seen_variants.add(payload)

    _add_variant("original message", message)

    if _ML_DSA_SIGNATURE_CONTEXT:
        context = bytes(_ML_DSA_SIGNATURE_CONTEXT)
        context_label = _ML_DSA_SIGNATURE_CONTEXT_LABEL

        prefixed = context + message
        if prefixed:
            _add_variant(f"'{context_label}' prefix + message", prefixed)

        nul_prefixed = context + b"\x00" + message
        if nul_prefixed:
            _add_variant(
                f"'{context_label}' prefix + NUL separator + message", nul_prefixed
            )

    base_variants_snapshot = list(fallback_variants)
    for base_label, base_payload in base_variants_snapshot:
        for digest_name, digest_factory in digest_functions:
            digest = digest_factory(base_payload).digest()
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
                fallback_attempts=tuple(fallback_attempts),
            )

    base_result = False
    return base_result, _MLDSAContextResult(
        supported=context_supported,
        attempted=context_attempted,
        succeeded=context_succeeded,
        error=context_error,
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
                "oqs bindings do not expose verify_with_ctx_str; context-aware "
                "ML-DSA verification unavailable."
            )
        elif context_result.attempted:
            if context_result.succeeded is True:
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}' succeeded."
                )
            elif context_result.succeeded is False:
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}' failed; falling back to "
                    "context-free verification."
                )
            else:
                parts.append(
                    "Context-aware ML-DSA verification using "
                    f"'{context_result.label}' raised "
                    f"{context_result.error!r}; falling back to context-free verification."
                )
        else:
            parts.append(
                "verify_with_ctx_str was available but no context attempt was made."
            )

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
        parameter_set = "ML-DSA-44"
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
