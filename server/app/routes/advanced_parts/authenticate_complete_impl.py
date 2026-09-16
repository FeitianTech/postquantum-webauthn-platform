from __future__ import annotations

import base64
from typing import Any, Dict, List, Mapping, Optional

from fido2.cose import CoseKey, UnsupportedKey

#: The ceremony challenge was taken from the server-side Flask session.
CHALLENGE_SOURCE_SERVER = "server-session"
#: The ceremony challenge was taken from the request body (request-editor mode).
CHALLENGE_SOURCE_CLIENT = "client-supplied"


def _credential_cose_algorithm(record: Optional[Mapping[str, Any]]) -> Optional[int]:
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


def _server_supports_algorithm(algorithm: Optional[int]) -> bool:
    """Return ``True`` when this server can actually verify ``algorithm``."""

    if not isinstance(algorithm, int):
        return False
    try:
        return CoseKey.for_alg(algorithm) is not UnsupportedKey
    except Exception:
        return False


def advanced_authenticate_complete_impl(advanced_module: Any):
    data = advanced_module.request.get_json(silent=True) or {}

    response = data.get("__assertion_response")
    if not response:
        return advanced_module.jsonify({"error": "Assertion response is required"}), 400

    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    public_key_raw = original_request.get("publicKey")
    if not isinstance(public_key_raw, Mapping):
        return advanced_module.jsonify(
            {"error": "Invalid request: Missing publicKey in JSON editor content"},
        ), 400

    public_key = public_key_raw

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials_list = list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else []
    resident_key_only = not allow_credentials_list

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    request_allowed_attachments = advanced_module.resolve_effective_attachments(hints_list, None)

    session_allowed_marker = advanced_module.session.pop("advanced_authenticate_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = advanced_module.normalize_attachment_list(session_allowed_marker)

    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    if allowed_attachments:
        response_attachment = advanced_module.normalize_attachment(
            response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
        )
        if response_attachment is None:
            return advanced_module.jsonify(
                {
                    "error": (
                        "Authenticator attachment could not be determined to enforce selected hints."
                    )
                }
            ), 400
        if response_attachment not in allowed_attachments:
            return advanced_module.jsonify(
                {"error": "Authenticator attachment is not permitted by the selected hints."},
            ), 400

    raw_credentials_input: Optional[List[Any]] = None
    for field in ("__storedCredentials", "storedCredentials", "credentials"):
        candidate = data.get(field)
        if isinstance(candidate, list):
            raw_credentials_input = candidate
            break

    stored_records: List[Dict[str, Any]] = []
    serialized_credentials: List[Dict[str, Any]] = []
    if isinstance(raw_credentials_input, list):
        stored_records, serialized_credentials = advanced_module._parse_client_supplied_credentials(raw_credentials_input)

    if not stored_records:
        legacy_serialized = advanced_module.session.pop("advanced_auth_credentials", [])
        if legacy_serialized:
            stored_records, serialized_credentials = advanced_module._parse_client_supplied_credentials(
                legacy_serialized,
            )

    if not stored_records:
        if isinstance(raw_credentials_input, list) and raw_credentials_input:
            advanced_module.session.pop("advanced_auth_credentials_meta", None)
            return advanced_module.jsonify(
                {
                    "error": (
                        "Stored credentials could not be restored from the browser session. "
                        "This often means the session cookie exceeded the browser size limit. "
                        "Please clear some saved credentials or restart the authentication flow and try again."
                    )
                }
            ), 400
        advanced_module.session.pop("advanced_auth_credentials_meta", None)
        return advanced_module.jsonify({"error": "No credentials found"}), 404

    advanced_module.session.pop("advanced_auth_credentials_meta", None)

    credential_lookup: Dict[bytes, Dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    all_credentials = [record["data"] for record in stored_records if record.get("data") is not None]

    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}
    credential_id_bytes = advanced_module._extract_assertion_credential_id(response_mapping)
    selected_record = credential_lookup.get(credential_id_bytes) if credential_id_bytes else None

    if resident_key_only and selected_record is not None and not selected_record.get("resident"):
        response_payload = {
            "error": (
                "The credential used is not discoverable. Please register a resident key credential to "
                "authenticate without allowCredentials."
            )
        }
        if credential_id_bytes:
            response_payload["failedCredentialId"] = (
                base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
            )
        return advanced_module.jsonify(response_payload), 400

    state = advanced_module.session.pop("advanced_auth_state", None)
    challenge_source = CHALLENGE_SOURCE_SERVER if state is not None else CHALLENGE_SOURCE_CLIENT
    if state is None:
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state
    if state is None:
        advanced_module.session.pop("advanced_auth_rp", None)
        return advanced_module.jsonify(
            {
                "error": (
                    "Authentication state not found or has expired. "
                    "Please restart the authentication flow."
                ),
                "challengeSource": challenge_source,
            }
        ), 400

    ceremony_origin = advanced_module.extract_client_data_origin(
        response.get("response") if isinstance(response, Mapping) else None
    )
    if not advanced_module.is_origin_allowed(ceremony_origin):
        advanced_module.session.pop("advanced_auth_rp", None)
        return advanced_module.jsonify(
            {
                "error": (
                    "Ceremony origin is not permitted by the configured "
                    "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                ),
                "challengeSource": challenge_source,
            }
        ), 400

    try:
        stored_rp = advanced_module.session.pop("advanced_auth_rp", None)
        stored_rp_id = None
        stored_rp_name = None
        if isinstance(stored_rp, Mapping):
            stored_rp_id = stored_rp.get("id")
            stored_rp_name = stored_rp.get("name")
        elif isinstance(advanced_module.session.get("advanced_rp"), Mapping):
            fallback_rp = advanced_module.session.get("advanced_rp")
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

        resolved_rp_id = advanced_module.determine_rp_id(stored_rp_id)
        auth_server = advanced_module.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

        derived_algorithms = advanced_module._derive_algorithms_from_credentials(all_credentials)
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
            # An assertion whose signature does not verify is NEVER reported as
            # OK. The only distinction made here is a diagnostic one: whether
            # this server can verify the credential's algorithm at all.
            response_mapping = response if isinstance(response, Mapping) else {}
            credential_id = advanced_module._extract_assertion_credential_id(response_mapping)
            record = credential_lookup.get(credential_id) if credential_id else None

            # Read the algorithm from the credential's own COSE key, not from
            # the client-supplied "algorithm" field next to it.
            credential_alg = _credential_cose_algorithm(record)
            failed_credential_id = None
            if credential_id:
                failed_credential_id = (
                    base64.urlsafe_b64encode(credential_id).decode("ascii").rstrip("=")
                )

            if credential_alg is not None and not _server_supports_algorithm(credential_alg):
                advanced_module.app.logger.warning(
                    "Assertion uses COSE algorithm %d which this server cannot verify; "
                    "no signature verification was performed.",
                    credential_alg,
                )
                unsupported_payload: Dict[str, Any] = {
                    "status": "UNSUPPORTED_ALGORITHM",
                    "verified": False,
                    "signatureVerified": False,
                    "error": (
                        f"COSE algorithm {credential_alg} is not supported by this server. "
                        "No signature verification was performed, so this assertion is "
                        "NOT verified."
                    ),
                    "algorithm": credential_alg,
                    "algorithmDescription": advanced_module.describe_algorithm(credential_alg),
                    "challengeSource": challenge_source,
                    "verificationError": str(exc),
                }
                if failed_credential_id is not None:
                    unsupported_payload["failedCredentialId"] = failed_credential_id
                return advanced_module.jsonify(unsupported_payload), 400

            signature_payload: Dict[str, Any] = {
                "status": "VERIFICATION_FAILED",
                "verified": False,
                "signatureVerified": False,
                "error": str(exc),
                "challengeSource": challenge_source,
            }
            if credential_alg is not None:
                signature_payload["algorithm"] = credential_alg
                signature_payload["algorithmDescription"] = advanced_module.describe_algorithm(
                    credential_alg
                )
            if failed_credential_id is not None:
                signature_payload["failedCredentialId"] = failed_credential_id
            return advanced_module.jsonify(signature_payload), 400
        else:
            try:
                result_public_key = getattr(auth_result, "public_key", None)
                if isinstance(result_public_key, Mapping):
                    auth_alg = result_public_key.get(3)
                else:
                    auth_alg = getattr(result_public_key, "get", lambda *_: None)(3)
            except Exception:
                auth_alg = None

        advanced_module.log_algorithm_selection("authentication", auth_alg)

        debug_info: Dict[str, Any] = {"hintsUsed": public_key.get("hints", [])}

        authenticated_id = None
        if credential_id_bytes:
            authenticated_id = base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")

        sign_count_value = None
        credential_response = response.get("response", {}) if isinstance(response, Mapping) else {}
        if isinstance(credential_response, Mapping):
            auth_data_b64 = credential_response.get("authenticatorData")
            if isinstance(auth_data_b64, str):
                try:
                    auth_data_bytes = advanced_module._decode_base64url(auth_data_b64)
                    sign_count_value = advanced_module.AuthenticatorData(auth_data_bytes).counter
                except Exception:
                    sign_count_value = None

        if auth_alg is not None:
            debug_info["algorithm"] = auth_alg
            debug_info["algorithmDescription"] = advanced_module.describe_algorithm(auth_alg)

        response_payload: Dict[str, Any] = {
            "status": "OK",
            "verified": True,
            "signatureVerified": True,
            "challengeSource": challenge_source,
            **debug_info,
        }
        if authenticated_id is not None:
            response_payload["authenticatedCredentialId"] = authenticated_id
        if sign_count_value is not None:
            response_payload["signCount"] = sign_count_value

        return advanced_module.jsonify(response_payload)
    except Exception as exc:
        response_payload: Dict[str, Any] = {
            "error": str(exc),
            "challengeSource": challenge_source,
        }
        failed_credential_id = credential_id_bytes
        if not failed_credential_id and isinstance(response, Mapping):
            failed_credential_id = advanced_module._extract_assertion_credential_id(response)
        if failed_credential_id:
            response_payload["failedCredentialId"] = (
                base64.urlsafe_b64encode(failed_credential_id).decode("ascii").rstrip("=")
            )
        return advanced_module.jsonify(response_payload), 400
