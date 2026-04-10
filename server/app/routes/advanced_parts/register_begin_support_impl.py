from __future__ import annotations

from typing import Any, Dict, List, Mapping


def configure_allowed_algorithms(
    advanced_module: Any,
    public_key: Mapping[str, Any],
    temp_server: Any,
    warnings: List[str],
) -> None:
    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        allowed_algorithms: List[Any] = []
        normalized_params: List[Dict[str, Any]] = []
        for param in pub_key_cred_params:
            raw_alg_value: Any
            if isinstance(param, Mapping):
                raw_alg_value = param.get("alg")
                if raw_alg_value is None:
                    raw_alg_value = param.get("id")
                if raw_alg_value is None:
                    raw_alg_value = param.get("value")

                type_value = param.get("type")
                if isinstance(type_value, str):
                    if type_value.strip().lower() != "public-key":
                        continue
                elif type_value is not None:
                    continue

                alg_value = advanced_module._coerce_cose_algorithm(raw_alg_value)
                if alg_value is None:
                    continue
                normalized_params.append({"type": "public-key", "alg": alg_value})
            else:
                alg_value = advanced_module._coerce_cose_algorithm(param)
                if alg_value is None:
                    continue
                normalized_params.append({"type": "public-key", "alg": alg_value})

            allowed_algorithms.append(
                advanced_module.PublicKeyCredentialParameters(
                    type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                    alg=alg_value,
                )
            )

        if normalized_params:
            public_key["pubKeyCredParams"] = normalized_params
        if allowed_algorithms:
            temp_server.allowed_algorithms = allowed_algorithms
    else:
        temp_server.allowed_algorithms = [
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=-50,
            ),
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=-48,
            ),
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=-49,
            ),
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7,
            ),
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=-257,
            ),
        ]

    allowed_algorithm_ids = [
        getattr(param, "alg", None)
        for param in getattr(temp_server, "allowed_algorithms", [])
    ]
    allowed_algorithm_ids = [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    pqc_in_allowed = {alg for alg in allowed_algorithm_ids if advanced_module.is_pqc_algorithm(alg)}
    if not pqc_in_allowed:
        return

    pqc_available_ids, pqc_error_message = advanced_module.detect_available_pqc_algorithms()
    missing_pqc = pqc_in_allowed - pqc_available_ids
    if not missing_pqc:
        return

    missing_names = ", ".join(
        advanced_module.PQC_ALGORITHM_ID_TO_NAME[alg] for alg in sorted(missing_pqc)
    )
    if pqc_error_message:
        advanced_module.app.logger.warning("Post-quantum support unavailable: %s", pqc_error_message)
    else:
        advanced_module.app.logger.warning(
            "Post-quantum algorithms requested (%s) but not available in this environment.",
            missing_names,
        )

    filtered_allowed = [
        param for param in temp_server.allowed_algorithms if getattr(param, "alg", None) not in missing_pqc
    ]
    fallback_applied = False
    if not filtered_allowed:
        temp_server.allowed_algorithms = [
            advanced_module.PublicKeyCredentialParameters(
                type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                alg=alg_value,
            )
            for alg_value in (-7, -8, -257)
        ]
        fallback_applied = True
    else:
        temp_server.allowed_algorithms = filtered_allowed

    if fallback_applied:
        warnings.append(
            f"Unsupported PQC algorithms were skipped ({missing_names}); falling back to classical algorithms."
        )
    else:
        warnings.append(f"Unsupported PQC algorithms were skipped ({missing_names}).")


def build_exclude_list(advanced_module: Any, public_key: Mapping[str, Any]) -> List[Any]:
    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = advanced_module._extract_binary_value(exclude_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    exclude_list.append(
                        advanced_module.PublicKeyCredentialDescriptor(
                            type=advanced_module.PublicKeyCredentialType.PUBLIC_KEY,
                            id=cred_id,
                        )
                    )
    return exclude_list


def build_processed_extensions(advanced_module: Any, public_key: Mapping[str, Any]) -> Dict[str, Any]:
    extensions = public_key.get("extensions", {})
    processed_extensions: Dict[str, Any] = {}

    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            if isinstance(ext_value, int):
                protect_map = {
                    1: "userVerificationOptional",
                    2: "userVerificationOptionalWithCredentialIDList",
                    3: "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = protect_map.get(ext_value, ext_value)
            elif isinstance(ext_value, str):
                alias_map = {
                    "userVerificationOptional": "userVerificationOptional",
                    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationRequired": "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = alias_map.get(ext_value, ext_value)
            else:
                processed_extensions["credentialProtectionPolicy"] = ext_value
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredentialProtectionPolicy"] = bool(ext_value)
        elif ext_name == "largeBlob":
            processed_extensions["largeBlob"] = {"support": ext_value} if isinstance(ext_value, str) else ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if isinstance(prf_eval, dict):
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
                processed_extensions["prf"] = {"eval": processed_eval} if processed_eval else ext_value
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    return processed_extensions
