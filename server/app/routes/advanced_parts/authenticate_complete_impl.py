from __future__ import annotations

import base64
from typing import Any, Dict, List, Mapping, Optional


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
                )
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

        fallback_used = False

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
            response_mapping = response if isinstance(response, Mapping) else {}
            credential_id = advanced_module._extract_assertion_credential_id(response_mapping)
            record = credential_lookup.get(credential_id) if credential_id else None
            stored_alg_value: Optional[int] = None
            if isinstance(record, Mapping):
                stored_alg = record.get("algorithm")
                if isinstance(stored_alg, int):
                    stored_alg_value = stored_alg

            requested_alg = advanced_module._extract_requested_assertion_algorithm(public_key, credential_id)
            error_message = str(exc).lower()
            signature_related = (
                not error_message
                or any(keyword in error_message for keyword in ("signature", "algorithm", "unsupported", "verify"))
            )

            if (
                stored_alg_value is not None
                and advanced_module._is_custom_cose_algorithm(stored_alg_value)
                and (requested_alg is None or requested_alg == stored_alg_value)
                and signature_related
            ):
                fallback_used = True
                auth_alg = stored_alg_value
                advanced_module.app.logger.warning(
                    "Accepting assertion using custom COSE algorithm %d without signature verification.",
                    stored_alg_value,
                )
            else:
                raise
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

        if fallback_used:
            debug_info["customAlgorithmBypass"] = True

        response_payload: Dict[str, Any] = {"status": "OK", **debug_info}
        if authenticated_id is not None:
            response_payload["authenticatedCredentialId"] = authenticated_id
        if sign_count_value is not None:
            response_payload["signCount"] = sign_count_value

        return advanced_module.jsonify(response_payload)
    except Exception as exc:
        response_payload: Dict[str, Any] = {"error": str(exc)}
        failed_credential_id = credential_id_bytes
        if not failed_credential_id and isinstance(response, Mapping):
            failed_credential_id = advanced_module._extract_assertion_credential_id(response)
        if failed_credential_id:
            response_payload["failedCredentialId"] = (
                base64.urlsafe_b64encode(failed_credential_id).decode("ascii").rstrip("=")
            )
        return advanced_module.jsonify(response_payload), 400
