from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from flask import jsonify, request, session

from fido2.cose import CoseKey, UnsupportedKey
from fido2.webauthn import AuthenticatorData, UserVerificationRequirement

from ... import attestation, config, pqc
from ...attachments import (
    normalize_attachment,
    normalize_attachment_list,
    resolve_effective_attachments,
)
from ...challenge_registry import consume_ceremony_state, stamp_ceremony_state
from ...encoding import decode_hex, encode_base64url
from ...sign_count import sign_count_status
from .. import binary_helpers
from . import algorithms, binary, parsing


def advanced_authenticate_begin():
    data = request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return jsonify(
            {"error": "Invalid request: Missing publicKey in CredentialRequestOptions"},
        ), 400

    public_key = data["publicKey"]

    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    raw_hints = public_key.get("hints")
    hints_list: list[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    allowed_attachment_values = resolve_effective_attachments(hints_list, None)
    session["advanced_authenticate_allowed_attachments"] = list(allowed_attachment_values)

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = binary._extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = decode_hex(challenge_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    stored_rp = session.get("advanced_rp")
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")

    resolved_rp_id = config.determine_rp_id(stored_rp_id)
    temp_server = config.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None

    user_verification = public_key.get("userVerification", "preferred")
    uv_req = UserVerificationRequirement.PREFERRED
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED

    raw_credentials_input: list[Any] = []
    for field in ("__storedCredentials", "storedCredentials", "credentials"):
        candidate = data.get(field)
        if isinstance(candidate, list):
            raw_credentials_input = candidate
            break

    stored_records, serialized_credentials = parsing._parse_client_supplied_credentials(raw_credentials_input)
    if not stored_records:
        return jsonify(
            {"error": "No credentials detected. Please register a credential first."},
        ), 404

    credential_lookup: dict[bytes, dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials: list[Any] = list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else []
    allow_credentials_present = bool(allow_credentials)
    resident_key_only = not allow_credentials_present
    credentials_for_begin: list[Any] = []
    resident_records: list[dict[str, Any]] = []

    if allow_credentials_present:
        seen_ids: set[bytes] = set()
        for allow_cred in allow_credentials:
            if not isinstance(allow_cred, dict) or allow_cred.get("type") != "public-key":
                continue

            cred_id = binary._extract_binary_value(allow_cred.get("id", ""))
            if isinstance(cred_id, str):
                try:
                    cred_id = decode_hex(cred_id)
                except ValueError:
                    continue

            if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                continue

            cred_id_bytes = bytes(cred_id)
            if cred_id_bytes in seen_ids:
                continue

            record = credential_lookup.get(cred_id_bytes)
            if record is None:
                continue

            attachment_value = record.get("attachment")
            if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                continue

            credentials_for_begin.append(record["data"])
            seen_ids.add(cred_id_bytes)

        if not credentials_for_begin:
            seen_ids.clear()
            for record in stored_records:
                cred_id = record.get("id")
                if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                    continue
                cred_id_bytes = bytes(cred_id)
                if cred_id_bytes in seen_ids:
                    continue
                attachment_value = record.get("attachment")
                if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                    continue
                credentials_for_begin.append(record["data"])
                seen_ids.add(cred_id_bytes)
    else:
        resident_records = [record for record in stored_records if record.get("resident")]
        seen_ids: set[bytes] = set()
        candidate_records = resident_records if resident_key_only and resident_records else stored_records
        for record in candidate_records:
            cred_id = record.get("id")
            if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                continue
            cred_id_bytes = bytes(cred_id)
            if cred_id_bytes in seen_ids:
                continue
            attachment_value = record.get("attachment")
            if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                continue
            credentials_for_begin.append(record["data"])
            seen_ids.add(cred_id_bytes)

    if not credentials_for_begin and not resident_key_only:
        if allowed_attachment_values:
            return jsonify(
                {
                    "error": (
                        "No credentials matched the selected hints. "
                        "Please adjust your hints or select different credentials."
                    )
                }
            ), 404
        return jsonify(
            {"error": "No matching credentials found. Please register first."},
        ), 404

    if resident_key_only and resident_records and not credentials_for_begin:
        if allowed_attachment_values:
            return jsonify(
                {
                    "error": (
                        "No resident key credentials matched the selected hints. "
                        "Please adjust your hints or register a discoverable credential."
                    )
                }
            ), 404
        return jsonify(
            {
                "error": (
                    "No resident key credentials are available. "
                    "Please register a discoverable credential first."
                )
            }
        ), 404

    algorithm_source: Iterable[Any]
    if credentials_for_begin:
        algorithm_source = credentials_for_begin
    else:
        algorithm_source = [record["data"] for record in stored_records if record.get("data") is not None]

    derived_algorithms = algorithms._derive_algorithms_from_credentials(algorithm_source)
    if derived_algorithms:
        temp_server.allowed_algorithms = derived_algorithms

    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            if isinstance(ext_value, dict):
                if ext_value.get("read"):
                    processed_extensions["largeBlob"] = {"read": True}
                elif ext_value.get("write"):
                    write_value = binary._extract_binary_value(ext_value["write"])
                    if isinstance(write_value, str):
                        write_value = decode_hex(write_value)
                    processed_extensions["largeBlob"] = {"write": write_value}
                else:
                    processed_extensions["largeBlob"] = ext_value
            else:
                processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if "first" in prf_eval:
                    first_value = binary._extract_binary_value(prf_eval["first"])
                    if isinstance(first_value, str):
                        first_value = decode_hex(first_value)
                    processed_eval["first"] = first_value
                if "second" in prf_eval:
                    second_value = binary._extract_binary_value(prf_eval["second"])
                    if isinstance(second_value, str):
                        second_value = decode_hex(second_value)
                    processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    credentials_argument: list[Any] | None = credentials_for_begin if credentials_for_begin else None
    options, state = temp_server.authenticate_begin(
        credentials_argument,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    # Stamped so /complete can tell a fresh state from one replayed out of an
    # old cookie. The copy echoed to the request editor is left unstamped.
    session["advanced_auth_state"] = stamp_ceremony_state(dict(state))
    session["advanced_auth_rp"] = {"id": resolved_rp_id, "name": stored_rp_name}
    session["advanced_auth_credentials_meta"] = {
        "count": len(serialized_credentials),
        "resident_count": sum(1 for entry in serialized_credentials if entry.get("resident")),
    }

    options_payload = dict(options)
    options_payload["__session_state"] = attestation.make_json_safe(state)
    public_key_dict = options_payload.get("publicKey")
    if isinstance(public_key_dict, Mapping):
        allow_list = public_key_dict.get("allowCredentials")
        if resident_key_only or allow_list is None:
            public_key_dict.pop("allowCredentials", None)

    return jsonify(attestation.make_json_safe(options_payload))


CHALLENGE_SOURCE_SERVER = "server-session"
#: The ceremony challenge was taken from the request body (request-editor mode).
CHALLENGE_SOURCE_CLIENT = "client-supplied"

#: A client-supplied challenge is not single-use tracked: the request editor
#: chooses it, so there is nothing for the server to consume.
CHALLENGE_STATUS_NOT_TRACKED = "not-tracked"


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


def advanced_authenticate_complete():
    data = request.get_json(silent=True) or {}

    # Determined up front (peek, not pop) so that every response below can
    # report it: the advanced flow may be permissive, never silent.
    challenge_source = (
        CHALLENGE_SOURCE_SERVER
        if session.get("advanced_auth_state") is not None
        else CHALLENGE_SOURCE_CLIENT
    )

    def _fail(payload: dict[str, Any], status: int = 400):
        payload.setdefault("challengeSource", challenge_source)
        return jsonify(payload), status

    response = data.get("__assertion_response")
    if not response:
        return _fail({"error": "Assertion response is required"})

    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    public_key_raw = original_request.get("publicKey")
    if not isinstance(public_key_raw, Mapping):
        return _fail({"error": "Invalid request: Missing publicKey in JSON editor content"})

    public_key = public_key_raw

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials_list = list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else []
    resident_key_only = not allow_credentials_list

    raw_hints = public_key.get("hints")
    hints_list: list[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    request_allowed_attachments = resolve_effective_attachments(hints_list, None)

    session_allowed_marker = session.pop("advanced_authenticate_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = normalize_attachment_list(session_allowed_marker)

    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    if allowed_attachments:
        response_attachment = normalize_attachment(
            response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
        )
        if response_attachment is None:
            return _fail(
                {
                    "error": (
                        "Authenticator attachment could not be determined to enforce selected hints."
                    )
                }
            )
        if response_attachment not in allowed_attachments:
            return _fail(
                {"error": "Authenticator attachment is not permitted by the selected hints."}
            )

    raw_credentials_input: list[Any] | None = None
    for field in ("__storedCredentials", "storedCredentials", "credentials"):
        candidate = data.get(field)
        if isinstance(candidate, list):
            raw_credentials_input = candidate
            break

    stored_records: list[dict[str, Any]] = []
    serialized_credentials: list[dict[str, Any]] = []
    if isinstance(raw_credentials_input, list):
        stored_records, serialized_credentials = parsing._parse_client_supplied_credentials(raw_credentials_input)

    if not stored_records:
        legacy_serialized = session.pop("advanced_auth_credentials", [])
        if legacy_serialized:
            stored_records, serialized_credentials = parsing._parse_client_supplied_credentials(
                legacy_serialized,
            )

    if not stored_records:
        if isinstance(raw_credentials_input, list) and raw_credentials_input:
            session.pop("advanced_auth_credentials_meta", None)
            return _fail(
                {
                    "error": (
                        "Stored credentials could not be restored from the browser session. "
                        "This often means the session cookie exceeded the browser size limit. "
                        "Please clear some saved credentials or restart the authentication flow and try again."
                    )
                }
            )
        session.pop("advanced_auth_credentials_meta", None)
        return _fail({"error": "No credentials found"}, 404)

    session.pop("advanced_auth_credentials_meta", None)

    credential_lookup: dict[bytes, dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    all_credentials = [record["data"] for record in stored_records if record.get("data") is not None]

    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}
    credential_id_bytes = binary_helpers.extract_assertion_credential_id(response_mapping)
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
                encode_base64url(credential_id_bytes)
            )
        return _fail(response_payload)

    state = session.pop("advanced_auth_state", None)
    if state is not None:
        # The request editor is permissive, so a replayed or stale server
        # challenge is reported via ``challengeStatus`` rather than rejected.
        # It is still consumed, so a replay is always labelled as one.
        challenge_status = consume_ceremony_state(state)
    else:
        challenge_status = CHALLENGE_STATUS_NOT_TRACKED
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state
    if state is None:
        session.pop("advanced_auth_rp", None)
        return jsonify(
            {
                "error": (
                    "Authentication state not found or has expired. "
                    "Please restart the authentication flow."
                ),
                "challengeSource": challenge_source,
                "challengeStatus": challenge_status,
            }
        ), 400

    ceremony_origin = config.extract_client_data_origin(
        response.get("response") if isinstance(response, Mapping) else None
    )
    if not config.is_origin_allowed(ceremony_origin):
        session.pop("advanced_auth_rp", None)
        return jsonify(
            {
                "error": (
                    "Ceremony origin is not permitted by the configured "
                    "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                ),
                "challengeSource": challenge_source,
                "challengeStatus": challenge_status,
            }
        ), 400

    try:
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
            # An assertion whose signature does not verify is NEVER reported as
            # OK. The only distinction made here is a diagnostic one: whether
            # this server can verify the credential's algorithm at all.
            response_mapping = response if isinstance(response, Mapping) else {}
            credential_id = binary_helpers.extract_assertion_credential_id(response_mapping)
            record = credential_lookup.get(credential_id) if credential_id else None

            # Read the algorithm from the credential's own COSE key, not from
            # the client-supplied "algorithm" field next to it.
            credential_alg = _credential_cose_algorithm(record)
            failed_credential_id = None
            if credential_id:
                failed_credential_id = (
                    encode_base64url(credential_id)
                )

            if credential_alg is not None and not _server_supports_algorithm(credential_alg):
                config.app.logger.warning(
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
                    "challengeSource": challenge_source,
                    "challengeStatus": challenge_status,
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
                "challengeSource": challenge_source,
                "challengeStatus": challenge_status,
            }
            if credential_alg is not None:
                signature_payload["algorithm"] = credential_alg
                signature_payload["algorithmDescription"] = pqc.describe_algorithm(
                    credential_alg
                )
            if failed_credential_id is not None:
                signature_payload["failedCredentialId"] = failed_credential_id
            return jsonify(signature_payload), 400
        else:
            try:
                result_public_key = getattr(auth_result, "public_key", None)
                if isinstance(result_public_key, Mapping):
                    auth_alg = result_public_key.get(3)
                else:
                    auth_alg = getattr(result_public_key, "get", lambda *_: None)(3)
            except Exception:
                auth_alg = None

        pqc.log_algorithm_selection("authentication", auth_alg)

        debug_info: dict[str, Any] = {"hintsUsed": public_key.get("hints", [])}

        authenticated_id = None
        if credential_id_bytes:
            authenticated_id = encode_base64url(credential_id_bytes)

        sign_count_value = None
        credential_response = response.get("response", {}) if isinstance(response, Mapping) else {}
        if isinstance(credential_response, Mapping):
            auth_data_b64 = credential_response.get("authenticatorData")
            if isinstance(auth_data_b64, str):
                try:
                    auth_data_bytes = binary._decode_base64url(auth_data_b64)
                    sign_count_value = AuthenticatorData(auth_data_bytes).counter
                except Exception:
                    sign_count_value = None

        if auth_alg is not None:
            debug_info["algorithm"] = auth_alg
            debug_info["algorithmDescription"] = pqc.describe_algorithm(auth_alg)

        response_payload: dict[str, Any] = {
            "status": "OK",
            "verified": True,
            "signatureVerified": True,
            "challengeSource": challenge_source,
            "challengeStatus": challenge_status,
            **debug_info,
        }
        if authenticated_id is not None:
            response_payload["authenticatedCredentialId"] = authenticated_id
        if sign_count_value is not None:
            response_payload["signCount"] = sign_count_value
            # Reported, never enforced: the stored value is whatever the
            # request editor sent, so this is a diagnostic, not a clone check.
            stored_sign_count = (
                selected_record.get("signCount", 0) if isinstance(selected_record, Mapping) else 0
            )
            response_payload["signCountStatus"] = sign_count_status(
                stored_sign_count, sign_count_value
            )

        return jsonify(response_payload)
    except Exception as exc:
        response_payload: dict[str, Any] = {
            "error": str(exc),
            "challengeSource": challenge_source,
            "challengeStatus": challenge_status,
        }
        failed_credential_id = credential_id_bytes
        if not failed_credential_id and isinstance(response, Mapping):
            failed_credential_id = binary_helpers.extract_assertion_credential_id(response)
        if failed_credential_id:
            response_payload["failedCredentialId"] = (
                encode_base64url(failed_credential_id)
            )
        return jsonify(response_payload), 400
