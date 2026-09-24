"""Advanced authentication complete: fido2's verification and what the answer reports.

An assertion whose signature does not verify is never reported as OK. The one
distinction made on failure is diagnostic: whether this server can verify the
credential's algorithm at all (``UNSUPPORTED_ALGORITHM``) or it could and the
signature is wrong (``VERIFICATION_FAILED``). The signature counter is reported,
never enforced: the stored value is whatever the request editor sent.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from flask import jsonify, session

from fido2.cose import CoseKey, UnsupportedKey
from fido2.webauthn import AuthenticatorData

from ... import config
from ...encoding import encode_base64url
from ...webauthn import pqc
from ...webauthn.sign_count import sign_count_status
from .. import binary_helpers
from . import algorithms, binary

logger = logging.getLogger(__name__)


def _credential_cose_algorithm(record: Mapping[str, Any] | None) -> int | None:
    """Return the algorithm the credential's own COSE key declares (label 3).

    This is deliberately read from the parsed COSE key rather than from the
    client-supplied ``algorithm``/``publicKeyAlgorithm`` field, which is an
    independent, attacker-controlled value.
    """

    if not isinstance(record, Mapping):
        return None
    credential_data = record.get("data")
    public_key = getattr(credential_data, "public_key", None)
    if public_key is None:
        return None
    try:
        algorithm = public_key[3]
    except Exception:
        try:
            algorithm = public_key.get(3)  # type: ignore[union-attr]
        except Exception:
            return None
    return algorithm if isinstance(algorithm, int) else None


def _server_supports_algorithm(algorithm: int | None) -> bool:
    """Return ``True`` when this server can actually verify ``algorithm``."""

    if not isinstance(algorithm, int):
        return False
    try:
        return CoseKey.for_alg(algorithm) is not UnsupportedKey
    except Exception:
        return False


def _assertion_rp(public_key: Mapping[str, Any]) -> tuple[Any, Any]:
    """The RP id and name: begin's, else the last registration's, else the request's."""

    stored_rp = session.pop("advanced_auth_rp", None)
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")
    elif isinstance(session.get("advanced_rp"), Mapping):
        fallback_rp = session.get("advanced_rp")
        stored_rp_id = fallback_rp.get("id")
        stored_rp_name = fallback_rp.get("name")
    elif isinstance(public_key, Mapping):
        rp_candidate = public_key.get("rp")
        if isinstance(rp_candidate, Mapping):
            stored_rp_id = rp_candidate.get("id")
            stored_rp_name = rp_candidate.get("name")
        rp_id_candidate = public_key.get("rpId")
        if stored_rp_id is None and isinstance(rp_id_candidate, str):
            stored_rp_id = rp_id_candidate
    return stored_rp_id, stored_rp_name


def _verification_failure(exc: Exception, response: Any, lookup: Mapping[bytes, Any], trace: Mapping[str, Any]) -> Any:
    """The 400 for an assertion fido2 refused: UNSUPPORTED_ALGORITHM or VERIFICATION_FAILED."""

    response_mapping = response if isinstance(response, Mapping) else {}
    credential_id = binary_helpers.extract_assertion_credential_id(response_mapping)
    record = lookup.get(credential_id) if credential_id else None

    # Read the algorithm from the credential's own COSE key, not from
    # the client-supplied "algorithm" field next to it.
    credential_alg = _credential_cose_algorithm(record)
    failed_credential_id = None
    if credential_id:
        failed_credential_id = (
            encode_base64url(credential_id)
        )

    if credential_alg is not None and not _server_supports_algorithm(credential_alg):
        logger.warning(
            "Assertion uses COSE algorithm %d which this server cannot verify; "
            "no signature verification was performed.",
            credential_alg,
        )
        unsupported_payload: dict[str, Any] = {
            "status": "UNSUPPORTED_ALGORITHM",
            "verified": False,
            "signatureVerified": False,
            "error": (
                f"COSE algorithm {credential_alg} is not supported by this server. "
                "No signature verification was performed, so this assertion is "
                "NOT verified."
            ),
            "algorithm": credential_alg,
            "algorithmDescription": pqc.describe_algorithm(credential_alg),
            "challengeSource": trace["challengeSource"],
            "challengeStatus": trace["challengeStatus"],
            "verificationError": str(exc),
        }
        if failed_credential_id is not None:
            unsupported_payload["failedCredentialId"] = failed_credential_id
        return jsonify(unsupported_payload), 400

    signature_payload: dict[str, Any] = {
        "status": "VERIFICATION_FAILED",
        "verified": False,
        "signatureVerified": False,
        "error": str(exc),
        "challengeSource": trace["challengeSource"],
        "challengeStatus": trace["challengeStatus"],
    }
    if credential_alg is not None:
        signature_payload["algorithm"] = credential_alg
        signature_payload["algorithmDescription"] = pqc.describe_algorithm(
            credential_alg
        )
    if failed_credential_id is not None:
        signature_payload["failedCredentialId"] = failed_credential_id
    return jsonify(signature_payload), 400


def _result_algorithm(auth_result: Any) -> Any:
    try:
        result_public_key = getattr(auth_result, "public_key", None)
        if isinstance(result_public_key, Mapping):
            return result_public_key.get(3)
        return getattr(result_public_key, "get", lambda *_: None)(3)
    except Exception:
        return None


def _asserted_sign_count(response: Any) -> int | None:
    credential_response = response.get("response", {}) if isinstance(response, Mapping) else {}
    if isinstance(credential_response, Mapping):
        auth_data_b64 = credential_response.get("authenticatorData")
        if isinstance(auth_data_b64, str):
            try:
                auth_data_bytes = binary._decode_base64url(auth_data_b64)
                return AuthenticatorData(auth_data_bytes).counter
            except Exception:
                return None
    return None


def _verified_payload(
    *,
    auth_alg: Any,
    public_key: Mapping[str, Any],
    response: Any,
    credential_id_bytes: bytes | None,
    selected_record: Any,
    trace: Mapping[str, Any],
) -> dict[str, Any]:
    debug_info: dict[str, Any] = {"hintsUsed": public_key.get("hints", [])}

    authenticated_id = None
    if credential_id_bytes:
        authenticated_id = encode_base64url(credential_id_bytes)

    sign_count_value = _asserted_sign_count(response)

    if auth_alg is not None:
        debug_info["algorithm"] = auth_alg
        debug_info["algorithmDescription"] = pqc.describe_algorithm(auth_alg)

    response_payload: dict[str, Any] = {
        "status": "OK",
        "verified": True,
        "signatureVerified": True,
        "challengeSource": trace["challengeSource"],
        "challengeStatus": trace["challengeStatus"],
        **debug_info,
    }
    if authenticated_id is not None:
        response_payload["authenticatedCredentialId"] = authenticated_id
    if sign_count_value is not None:
        response_payload["signCount"] = sign_count_value
        stored_sign_count = (
            selected_record.get("signCount", 0) if isinstance(selected_record, Mapping) else 0
        )
        response_payload["signCountStatus"] = sign_count_status(
            stored_sign_count, sign_count_value
        )
    return response_payload


def verify_assertion(
    *,
    data: Mapping[str, Any],
    state: Any,
    public_key: Mapping[str, Any],
    response: Any,
    all_credentials: list[Any],
    lookup: Mapping[bytes, Any],
    credential_id_bytes: bytes | None,
    selected_record: Any,
    trace: Mapping[str, Any],
) -> Any:
    """Have fido2 verify the assertion, and answer with what it concluded."""

    stored_rp_id, stored_rp_name = _assertion_rp(public_key)
    resolved_rp_id = config.determine_rp_id(stored_rp_id)
    auth_server = config.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

    derived_algorithms = algorithms._derive_algorithms_from_credentials(all_credentials)
    if derived_algorithms:
        auth_server.allowed_algorithms = derived_algorithms

    hash_algorithm = data.get("__hash_algorithm", "SHA-256")
    if not isinstance(hash_algorithm, str):
        hash_algorithm = "SHA-256"

    try:
        auth_result = auth_server.authenticate_complete(
            state,
            all_credentials,
            response,
            hash_algorithm=hash_algorithm,
        )
    except Exception as exc:
        return _verification_failure(exc, response, lookup, trace)

    auth_alg = _result_algorithm(auth_result)
    pqc.log_algorithm_selection("authentication", auth_alg)
    return jsonify(
        _verified_payload(
            auth_alg=auth_alg,
            public_key=public_key,
            response=response,
            credential_id_bytes=credential_id_bytes,
            selected_record=selected_record,
            trace=trace,
        )
    )
