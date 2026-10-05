"""What a registration response says against what was expected: its client data, its RP ID hash, its authenticator data's flags and credential."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from fido2.cose import CoseKey
from fido2.webauthn import AuthenticatorData, CollectedClientData

from ... import encoding
from . import request_expectations


def populate_client_data_results(
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
        "challenge": encoding.encode_base64url(client_data.challenge),
        "expected_challenge": (
            encoding.encode_base64url(expected_challenge_bytes)
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


def populate_rp_id_hash_result(
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


def populate_authenticator_data_results(
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

    uv_required = request_expectations.resolve_uv_required(state, public_key_options)
    uv_satisfied = user_verified or not uv_required

    if not user_present:
        results["errors"].append("user_presence_missing")
    if uv_required and not uv_satisfied:
        results["errors"].append("user_verification_required_not_satisfied")
    if not attested_credential_included:
        results["errors"].append("attested_credential_data_missing")

    allowed_algorithms = request_expectations.collect_allowed_algorithms(public_key_options)
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


def hash_binding(auth_data_obj: Any, client_data_hash: bytes) -> dict[str, str]:
    """The client data hash and the authData || hash the attestation signature covers."""

    verification_data = bytes(auth_data_obj) + client_data_hash
    return {
        "client_data_hash": encoding.encode_base64url(client_data_hash),
        "verification_data": encoding.encode_base64url(verification_data),
    }
