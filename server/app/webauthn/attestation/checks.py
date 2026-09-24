from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fido2.attestation import (
    Attestation,
    InvalidData,
    InvalidSignature,
    UnsupportedType,
)
from fido2.cose import CoseKey
from fido2.utils import ByteBuffer
from fido2.webauthn import (
    Aaguid,
    AuthenticatorData,
    CollectedClientData,
    RegistrationResponse,
)

from ... import encoding
from .. import metadata
from ..pqc import is_pqc_algorithm
from . import classical, formatting, pqc, trust


def _resolve_uv_required(
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
) -> bool:
    uv_required = False
    if isinstance(state, Mapping):
        state_uv = state.get("user_verification")
        if getattr(state_uv, "value", None) == "required" or state_uv == "required":
            uv_required = True

    if not uv_required and isinstance(public_key_options, Mapping):
        uv_setting: str | None = None
        authenticator_selection = public_key_options.get("authenticatorSelection")
        if isinstance(authenticator_selection, Mapping):
            uv_setting = authenticator_selection.get("userVerification")
        if not uv_setting:
            uv_setting = public_key_options.get("userVerification")
        if isinstance(uv_setting, str) and uv_setting.lower() == "required":
            uv_required = True

    return uv_required


def _collect_allowed_algorithms(
    public_key_options: Mapping[str, Any] | None,
) -> list[int]:
    allowed_algorithms: list[int] = []
    if isinstance(public_key_options, Mapping):
        params = public_key_options.get("pubKeyCredParams")
        if isinstance(params, list):
            for param in params:
                if isinstance(param, Mapping) and isinstance(param.get("alg"), int):
                    allowed_algorithms.append(param["alg"])
    return allowed_algorithms


def _metadata_entry_by_aaguid(verifier: Any, credential_aaguid_bytes: bytes) -> Any:
    """The metadata entry for the credential's AAGUID, or ``None``; a failed lookup is no entry."""

    try:
        aaguid_obj = Aaguid.fromhex(credential_aaguid_bytes.hex())
    except Exception:
        return None
    if verifier is None:
        verifier = metadata.get_mds_verifier()
    if verifier is None:
        return None
    try:
        return verifier.find_entry_by_aaguid(aaguid_obj)
    except Exception:
        return None


def _metadata_entry_facts(metadata_entry: Any, algorithm: Any) -> dict[str, Any]:
    """What an entry says: its description, root certificates, algorithms and AAGUID."""

    metadata_description: str | None = None
    metadata_aaguid: str | None = None
    metadata_algorithm_supported: bool | None = None
    metadata_root_certificates_present = False

    metadata_statement = getattr(metadata_entry, "metadata_statement", None)
    if getattr(metadata_statement, "description", None):
        metadata_description = metadata_statement.description
    authenticator_info = getattr(
        metadata_statement,
        "authenticator_get_info",
        None,
    )
    root_certs = getattr(
        metadata_statement,
        "attestation_root_certificates",
        None,
    )
    if not root_certs and isinstance(metadata_statement, dict):
        root_certs = metadata_statement.get("attestation_root_certificates") or metadata_statement.get(
            "attestationRootCertificates"
        )
    if isinstance(root_certs, (list, tuple, set)):
        metadata_root_certificates_present = any(bool(cert) for cert in root_certs)
    elif root_certs:
        metadata_root_certificates_present = True
    if (
        isinstance(authenticator_info, dict)
        and isinstance(algorithm, int)
    ):
        alg_list = authenticator_info.get("algorithms")
        if isinstance(alg_list, (list, tuple)):
            numeric_algs = [alg for alg in alg_list if isinstance(alg, int)]
            if numeric_algs:
                metadata_algorithm_supported = algorithm in numeric_algs
    # Reported, not compared with the credential's AAGUID: every entry here
    # was looked up by that AAGUID (fido2's ca_lookup whenever there is one,
    # the PQC path and the fallback above), so they cannot differ. The one
    # other lookup, by certificate chain, runs only for a credential with no
    # AAGUID -- fido-u2f's is zero by definition -- where they always would.
    entry_aaguid = getattr(metadata_entry, "aaguid", None)
    if entry_aaguid is not None:
        try:
            metadata_aaguid = str(entry_aaguid)
        except Exception:
            pass

    return {
        "description": metadata_description,
        "aaguid": metadata_aaguid,
        "algorithm_supported": metadata_algorithm_supported,
        "root_certificates_present": metadata_root_certificates_present,
    }


def _finalize_metadata_results(
    results: dict[str, Any],
    *,
    metadata_entry: Any,
    metadata_lookup_source: str | None,
    verifier: Any,
    credential_aaguid_bytes: bytes,
    certificate_aaguid_bytes: bytes,
    root_check_details: dict[str, bool | None] | None,
    root_valid: bool | None,
) -> None:
    if metadata_entry is None and credential_aaguid_bytes:
        fallback_entry = _metadata_entry_by_aaguid(verifier, credential_aaguid_bytes)
        if fallback_entry is not None:
            metadata_entry = fallback_entry
            metadata_lookup_source = "aaguid"

    facts: dict[str, Any] = {
        "description": None,
        "aaguid": None,
        "algorithm_supported": None,
        "root_certificates_present": False,
    }
    if metadata_entry is not None:
        facts = _metadata_entry_facts(metadata_entry, results["authenticator_data"].get("algorithm"))

    credential_aaguid_value = credential_aaguid_bytes if credential_aaguid_bytes else None
    certificate_aaguid_value = certificate_aaguid_bytes if certificate_aaguid_bytes else None

    if credential_aaguid_value and certificate_aaguid_value:
        results["aaguid_match"] = (
            credential_aaguid_value == certificate_aaguid_value
        )
    else:
        results["aaguid_match"] = None

    results["metadata"] = {"available": metadata_entry is not None, **facts}

    if metadata_lookup_source:
        results["metadata"]["source"] = metadata_lookup_source

    # The AAGUID exposed during registration originates from the attestation
    # object. Metadata mismatches are surfaced through ``results["metadata"]``,
    # while ``results["aaguid_match"]`` only reflects whether the authenticator
    # data and attestation certificate agree.
    if facts["algorithm_supported"] is False:
        results["errors"].append("algorithm_not_in_metadata")

    if root_check_details:
        results["root_checks"] = root_check_details

    if root_valid is not None:
        results["root_valid"] = root_valid


def _coerce_expected_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, ByteBuffer):
        return bytes(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        for decoder in (
            encoding.try_decode_base64url,
            encoding.try_decode_base64,
            encoding.try_decode_hex,
        ):
            decoded = decoder(value)
            if decoded is not None:
                return decoded
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        if "$base64url" in value:
            return _coerce_expected_bytes(value["$base64url"])
        if "$base64" in value:
            encoded = value["$base64"]
            if not isinstance(encoded, str):
                return b""
            return encoding.try_decode_base64(encoded) or b""
        if "$hex" in value:
            hex_value = value["$hex"]
            if not isinstance(hex_value, str):
                return b""
            return encoding.try_decode_hex(hex_value) or b""
    return b""


def _resolve_expected_challenge(
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
) -> bytes:
    expected_challenge_bytes = b""
    if isinstance(state, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(state.get("challenge"))
    if not expected_challenge_bytes and isinstance(public_key_options, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(
            public_key_options.get("challenge")
        )
    return expected_challenge_bytes


def _populate_client_data_results(
    results: dict[str, Any],
    *,
    client_data: Any,
    expected_challenge_bytes: bytes,
    expected_origin: str,
) -> str:
    challenge_matches = (
        bool(expected_challenge_bytes)
        and client_data.challenge == expected_challenge_bytes
    )

    expected_origin_normalized = (expected_origin or "").rstrip("/")
    origin_matches = bool(expected_origin_normalized) and (
        client_data.origin == expected_origin_normalized
    )

    results["client_data"] = {
        "type": client_data.type,
        "expected_type": CollectedClientData.TYPE.CREATE.value,
        "type_valid": client_data.type
        == CollectedClientData.TYPE.CREATE.value,
        "challenge": formatting.encode_base64url(client_data.challenge),
        "expected_challenge": (
            formatting.encode_base64url(expected_challenge_bytes)
            if expected_challenge_bytes
            else None
        ),
        "challenge_matches": challenge_matches,
        "origin": client_data.origin,
        "expected_origin": expected_origin_normalized,
        "origin_valid": origin_matches,
        "cross_origin": bool(client_data.cross_origin),
        "cross_origin_ok": not bool(client_data.cross_origin),
    }

    if not results["client_data"]["type_valid"]:
        results["errors"].append("client_data_type_invalid")
    if expected_challenge_bytes and not challenge_matches:
        results["errors"].append("challenge_mismatch")
    if expected_origin_normalized and not origin_matches:
        results["errors"].append("origin_mismatch")
    if bool(client_data.cross_origin):
        results["errors"].append("cross_origin_not_allowed")

    return expected_origin_normalized


def _populate_rp_id_hash_result(
    results: dict[str, Any],
    *,
    auth_data_obj: Any,
    rp_id: str,
) -> bool:
    rp_id_value = rp_id or ""
    rp_id_hash_expected = hashlib.sha256(rp_id_value.encode("utf-8")).digest()
    rp_id_hash_valid = auth_data_obj.rp_id_hash == rp_id_hash_expected
    results["rp_id_hash_valid"] = rp_id_hash_valid

    if not rp_id_hash_valid:
        results["errors"].append("rp_id_hash_mismatch")

    return rp_id_hash_valid


def _credential_facts(results: dict[str, Any], credential_data: Any) -> dict[str, Any]:
    """The credential id length, COSE algorithm and AAGUID; a COSE key that will not parse is an error."""

    credential_id_length: int | None = None
    credential_aaguid: str | None = None
    credential_aaguid_bytes = b""
    algorithm: int | None = None
    cose_key_valid = False

    if credential_data is not None:
        try:
            credential_id_length = len(credential_data.credential_id)
        except Exception:
            credential_id_length = None

        try:
            cose_map = dict(credential_data.public_key)
        except Exception:
            cose_map = {}

        try:
            if cose_map:
                algorithm = cose_map.get(3)
                CoseKey.parse(cose_map)
            else:
                algorithm = credential_data.public_key.get(3)
                CoseKey.parse(dict(credential_data.public_key))
            cose_key_valid = True
        except Exception as exc:
            if algorithm is None:
                try:
                    algorithm = credential_data.public_key.get(3)
                except Exception:
                    algorithm = None
            results["errors"].append(f"cose_key_error: {exc}")

        try:
            credential_aaguid_bytes = bytes(credential_data.aaguid)
            credential_aaguid = credential_aaguid_bytes.hex()
        except Exception:
            credential_aaguid_bytes = b""
            credential_aaguid = None

    return {
        "credential_id_length": credential_id_length,
        "credential_aaguid": credential_aaguid,
        "credential_aaguid_bytes": credential_aaguid_bytes,
        "algorithm": algorithm,
        "cose_key_valid": cose_key_valid,
    }


def _populate_authenticator_data_results(
    results: dict[str, Any],
    *,
    auth_data_obj: Any,
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
) -> dict[str, Any]:
    flags = auth_data_obj.flags
    user_present = bool(flags & AuthenticatorData.FLAG.UP)
    user_verified = bool(flags & AuthenticatorData.FLAG.UV)
    attested_credential_included = bool(flags & AuthenticatorData.FLAG.AT)

    uv_required = _resolve_uv_required(state, public_key_options)
    uv_satisfied = user_verified or not uv_required

    if not user_present:
        results["errors"].append("user_presence_missing")
    if uv_required and not uv_satisfied:
        results["errors"].append("user_verification_required_not_satisfied")
    if not attested_credential_included:
        results["errors"].append("attested_credential_data_missing")

    allowed_algorithms = _collect_allowed_algorithms(public_key_options)
    credential = _credential_facts(results, getattr(auth_data_obj, "credential_data", None))
    algorithm = credential["algorithm"]

    algorithm_allowed = True
    if allowed_algorithms:
        if isinstance(algorithm, int):
            algorithm_allowed = algorithm in allowed_algorithms
        else:
            algorithm_allowed = False

    if allowed_algorithms and not algorithm_allowed:
        results["errors"].append("algorithm_not_allowed")

    results["authenticator_data"] = {
        "user_present": user_present,
        "user_verified": user_verified,
        "user_verification_required": uv_required,
        "user_verification_satisfied": uv_satisfied,
        "attested_credential_data": attested_credential_included,
        "counter": auth_data_obj.counter,
        "credential_id_length": credential["credential_id_length"],
        "credential_aaguid": credential["credential_aaguid"],
        "algorithm": algorithm,
        "algorithm_allowed": algorithm_allowed,
        "cose_key_valid": credential["cose_key_valid"],
    }

    return {
        "algorithm": algorithm,
        "credential_aaguid_bytes": credential["credential_aaguid_bytes"],
        "allowed_algorithms": allowed_algorithms,
        "uv_required": uv_required,
    }


def _resolve_signature_validation(
    attestation_object: Any,
    client_data_hash: bytes,
) -> dict[str, Any]:
    attestation_format_value = (attestation_object.fmt or "").lower()
    attestation_result = None
    attestation_errors: list[str] = []

    if attestation_format_value == "none":
        signature_valid = None
    else:
        try:
            attestation_cls = Attestation.for_type(attestation_object.fmt)
            attestation_instance = attestation_cls()
            attestation_result = attestation_instance.verify(
                attestation_object.att_stmt,
                attestation_object.auth_data,
                client_data_hash,
            )
            signature_valid = True
        except UnsupportedType as exc:
            attestation_errors.append(f"unsupported_attestation: {exc}")
            signature_valid = False
        except (InvalidSignature, InvalidData) as exc:
            attestation_errors.append(f"attestation_invalid: {exc}")
            signature_valid = False
        except Exception as exc:
            attestation_errors.append(f"attestation_error: {exc}")
            signature_valid = False

    pqc_signature_valid: bool | None = None
    if signature_valid is False and attestation_format_value != "none":
        pqc_outcome = pqc._attempt_pqc_attestation_signature_validation(
            attestation_object, client_data_hash
        )
        if pqc_outcome.get("attempted"):
            pqc_error = pqc_outcome.get("error")
            if pqc_outcome.get("success"):
                # The PQC fallback checks the attestation SIGNATURE only; it
                # skips the packed-attestation certificate policy checks
                # (Subject OU, AAGUID extension match, Basic Constraints).
                # It is therefore reported as its own result and must never
                # overwrite the overall verdict or erase the errors that the
                # full verification produced.
                pqc_signature_valid = True
                attestation_result = pqc_outcome.get("attestation_result")
            else:
                pqc_signature_valid = False
                if pqc_error:
                    attestation_errors.append(str(pqc_error))

    return {
        "attestation_format_value": attestation_format_value,
        "signature_valid": signature_valid,
        "pqc_signature_valid": pqc_signature_valid,
        "attestation_result": attestation_result,
        "attestation_errors": attestation_errors,
    }


def _collect_attestation_trust_path(
    attestation_result: Any,
    attestation_object: Any,
) -> list[bytes]:
    attestation_trust_path: list[bytes] = []
    if attestation_result is not None:
        trust_path_candidate = getattr(attestation_result, "trust_path", None)
        if trust_path_candidate:
            attestation_trust_path = list(trust_path_candidate)
    if not attestation_trust_path and isinstance(attestation_object.att_stmt, Mapping):
        attestation_trust_path = trust._collect_trust_path_entries(
            attestation_object.att_stmt.get("x5c")
        )
    return attestation_trust_path


def _evaluate_root_validation(
    results: dict[str, Any],
    *,
    algorithm: int | None,
    attestation_object: Any,
    attestation_result: Any,
    client_data_hash: bytes,
    credential_aaguid_bytes: bytes,
    signature_valid: bool | None,
    attestation_format_value: str,
) -> dict[str, Any]:
    attestation_trust_path = _collect_attestation_trust_path(
        attestation_result,
        attestation_object,
    )

    certificate_aaguid_bytes = b""
    if attestation_trust_path:
        certificate_aaguid_bytes = trust._extract_certificate_aaguid(attestation_trust_path[0])

    metadata_entry = None
    metadata_lookup_source: str | None = None
    now = datetime.now(timezone.utc)
    root_valid: bool | None = None
    verifier = None
    root_check_details: dict[str, bool | None] | None = None

    pqc_registration = isinstance(algorithm, int) and is_pqc_algorithm(algorithm)
    if pqc_registration:
        verifier = metadata.get_mds_verifier()
        pqc_outcome = pqc._evaluate_mldsa_attestation_root(
            attestation_object,
            credential_aaguid_bytes,
            verifier,
            now,
        )
        root_valid = pqc_outcome.get("root_valid")
        metadata_entry = pqc_outcome.get("metadata_entry") or metadata_entry
        metadata_lookup_source = pqc_outcome.get("metadata_lookup_source")
        root_check_details = pqc_outcome.get("checks")
        pqc_errors = pqc_outcome.get("errors") or []
        pqc_warnings = pqc_outcome.get("warnings") or []
        if pqc_errors:
            results["errors"].extend(str(err) for err in pqc_errors)
        if pqc_warnings:
            results["warnings"].extend(str(warn) for warn in pqc_warnings)
    elif signature_valid and attestation_result is not None:
        verifier = metadata.get_mds_verifier()
        classical_outcome = classical._evaluate_classical_attestation_root(
            attestation_object,
            attestation_result,
            client_data_hash,
            verifier,
            now,
        )
        root_valid = classical_outcome.get("root_valid")
        if classical_outcome.get("metadata_entry") is not None:
            metadata_entry = classical_outcome.get("metadata_entry")
            metadata_lookup_source = classical_outcome.get("metadata_lookup_source")
        elif classical_outcome.get("metadata_lookup_source"):
            metadata_lookup_source = classical_outcome.get("metadata_lookup_source")
        root_check_details = classical_outcome.get("checks")
        class_errors = classical_outcome.get("errors") or []
        class_warnings = classical_outcome.get("warnings") or []
        if class_errors:
            results["errors"].extend(str(err) for err in class_errors)
        if class_warnings:
            results["warnings"].extend(str(warn) for warn in class_warnings)
    elif signature_valid is False and attestation_format_value != "none":
        results["errors"].append("attestation_signature_invalid")
        root_valid = False

    return {
        "root_valid": root_valid,
        "metadata_entry": metadata_entry,
        "metadata_lookup_source": metadata_lookup_source,
        "root_check_details": root_check_details,
        "verifier": verifier,
        "certificate_aaguid_bytes": certificate_aaguid_bytes,
    }


def _record_signature_result(results: dict[str, Any], signature_ctx: Mapping[str, Any]) -> None:
    for error_message in signature_ctx["attestation_errors"]:
        results["errors"].append(error_message)

    results["signature_valid"] = signature_ctx["signature_valid"]
    results["pqc_signature_valid"] = signature_ctx.get("pqc_signature_valid")


def _empty_results() -> dict[str, Any]:
    return {
        "attestation_format": None,
        "signature_valid": None,
        "pqc_signature_valid": None,
        "root_valid": None,
        "rp_id_hash_valid": None,
        "aaguid_match": None,
        "client_data": {},
        "authenticator_data": {},
        "metadata": {},
        "hash_binding": {},
        "errors": [],
        "warnings": [],
    }


def _hash_binding(auth_data_obj: Any, client_data_hash: bytes) -> dict[str, str]:
    """The client data hash and the authData || hash the attestation signature covers."""

    verification_data = bytes(auth_data_obj) + client_data_hash
    return {
        "client_data_hash": formatting.encode_base64url(client_data_hash),
        "verification_data": formatting.encode_base64url(verification_data),
    }


def perform_attestation_checks(
    response: Mapping[str, Any],
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
    auth_data: Any | None,
    expected_origin: str,
    rp_id: str,
) -> dict[str, Any]:
    """Execute a comprehensive set of attestation validation checks."""

    results = _empty_results()

    if not isinstance(response, Mapping):
        results["errors"].append("registration_response_invalid")
        return results

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:
        results["errors"].append(f"registration_parse_error: {exc}")
        return results

    client_data = registration.response.client_data
    attestation_object = registration.response.attestation_object
    results["attestation_format"] = attestation_object.fmt

    if isinstance(auth_data, AuthenticatorData):
        auth_data_obj = auth_data
    else:
        auth_data_obj = attestation_object.auth_data

    expected_challenge_bytes = _resolve_expected_challenge(state, public_key_options)
    _populate_client_data_results(
        results,
        client_data=client_data,
        expected_challenge_bytes=expected_challenge_bytes,
        expected_origin=expected_origin,
    )

    _populate_rp_id_hash_result(results, auth_data_obj=auth_data_obj, rp_id=rp_id)

    auth_ctx = _populate_authenticator_data_results(
        results,
        auth_data_obj=auth_data_obj,
        state=state,
        public_key_options=public_key_options,
    )

    client_data_hash = client_data.hash
    results["hash_binding"] = _hash_binding(auth_data_obj, client_data_hash)

    signature_ctx = _resolve_signature_validation(attestation_object, client_data_hash)
    _record_signature_result(results, signature_ctx)

    root_ctx = _evaluate_root_validation(
        results,
        algorithm=auth_ctx["algorithm"],
        attestation_object=attestation_object,
        attestation_result=signature_ctx["attestation_result"],
        client_data_hash=client_data_hash,
        credential_aaguid_bytes=auth_ctx["credential_aaguid_bytes"],
        signature_valid=signature_ctx["signature_valid"],
        attestation_format_value=signature_ctx["attestation_format_value"],
    )

    _finalize_metadata_results(
        results,
        metadata_entry=root_ctx["metadata_entry"],
        metadata_lookup_source=root_ctx["metadata_lookup_source"],
        verifier=root_ctx["verifier"],
        credential_aaguid_bytes=auth_ctx["credential_aaguid_bytes"],
        certificate_aaguid_bytes=root_ctx["certificate_aaguid_bytes"],
        root_check_details=root_ctx["root_check_details"],
        root_valid=root_ctx["root_valid"],
    )

    return results
