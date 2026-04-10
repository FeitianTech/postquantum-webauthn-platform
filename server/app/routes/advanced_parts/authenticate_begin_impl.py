from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional


def advanced_authenticate_begin_impl(advanced_module: Any):
    data = advanced_module.request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return advanced_module.jsonify(
            {"error": "Invalid request: Missing publicKey in CredentialRequestOptions"},
        ), 400

    public_key = data["publicKey"]

    if not public_key.get("challenge"):
        return advanced_module.jsonify({"error": "Missing required field: challenge"}), 400

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    allowed_attachment_values = advanced_module.resolve_effective_attachments(hints_list, None)
    advanced_module.session["advanced_authenticate_allowed_attachments"] = list(allowed_attachment_values)

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = advanced_module._extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as exc:
            return advanced_module.jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    stored_rp = advanced_module.session.get("advanced_rp")
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")

    resolved_rp_id = advanced_module.determine_rp_id(stored_rp_id)
    temp_server = advanced_module.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None

    user_verification = public_key.get("userVerification", "preferred")
    uv_req = advanced_module.UserVerificationRequirement.PREFERRED
    if user_verification == "required":
        uv_req = advanced_module.UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = advanced_module.UserVerificationRequirement.DISCOURAGED

    raw_credentials_input: List[Any] = []
    for field in ("__storedCredentials", "storedCredentials", "credentials"):
        candidate = data.get(field)
        if isinstance(candidate, list):
            raw_credentials_input = candidate
            break

    stored_records, serialized_credentials = advanced_module._parse_client_supplied_credentials(raw_credentials_input)
    if not stored_records:
        return advanced_module.jsonify(
            {"error": "No credentials detected. Please register a credential first."},
        ), 404

    credential_lookup: Dict[bytes, Dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials: List[Any] = list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else []
    allow_credentials_present = bool(allow_credentials)
    resident_key_only = not allow_credentials_present
    credentials_for_begin: List[Any] = []
    resident_records: List[Dict[str, Any]] = []

    if allow_credentials_present:
        seen_ids: set[bytes] = set()
        for allow_cred in allow_credentials:
            if not isinstance(allow_cred, dict) or allow_cred.get("type") != "public-key":
                continue

            cred_id = advanced_module._extract_binary_value(allow_cred.get("id", ""))
            if isinstance(cred_id, str):
                try:
                    cred_id = bytes.fromhex(cred_id)
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
            return advanced_module.jsonify(
                {
                    "error": (
                        "No credentials matched the selected hints. "
                        "Please adjust your hints or select different credentials."
                    )
                }
            ), 404
        return advanced_module.jsonify(
            {"error": "No matching credentials found. Please register first."},
        ), 404

    if resident_key_only and resident_records and not credentials_for_begin:
        if allowed_attachment_values:
            return advanced_module.jsonify(
                {
                    "error": (
                        "No resident key credentials matched the selected hints. "
                        "Please adjust your hints or register a discoverable credential."
                    )
                }
            ), 404
        return advanced_module.jsonify(
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

    derived_algorithms = advanced_module._derive_algorithms_from_credentials(algorithm_source)
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
                    write_value = advanced_module._extract_binary_value(ext_value["write"])
                    if isinstance(write_value, str):
                        write_value = bytes.fromhex(write_value)
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
                    first_value = advanced_module._extract_binary_value(prf_eval["first"])
                    if isinstance(first_value, str):
                        first_value = bytes.fromhex(first_value)
                    processed_eval["first"] = first_value
                if "second" in prf_eval:
                    second_value = advanced_module._extract_binary_value(prf_eval["second"])
                    if isinstance(second_value, str):
                        second_value = bytes.fromhex(second_value)
                    processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    credentials_argument: Optional[List[Any]] = credentials_for_begin if credentials_for_begin else None
    options, state = temp_server.authenticate_begin(
        credentials_argument,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    advanced_module.session["advanced_auth_state"] = state
    advanced_module.session["advanced_auth_rp"] = {"id": resolved_rp_id, "name": stored_rp_name}
    advanced_module.session["advanced_auth_credentials_meta"] = {
        "count": len(serialized_credentials),
        "resident_count": sum(1 for entry in serialized_credentials if entry.get("resident")),
    }

    options_payload = dict(options)
    options_payload["__session_state"] = advanced_module.make_json_safe(state)
    public_key_dict = options_payload.get("publicKey")
    if isinstance(public_key_dict, Mapping):
        allow_list = public_key_dict.get("allowCredentials")
        if resident_key_only or allow_list is None:
            public_key_dict.pop("allowCredentials", None)

    return advanced_module.jsonify(advanced_module.make_json_safe(options_payload))
