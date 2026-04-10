from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping


def register_begin_impl(simple_module: Any):
    payload = simple_module.request.get_json(silent=True) or {}

    existing_credentials_raw: List[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, serialized = simple_module._parse_client_credentials(existing_credentials_raw)
    if serialized:
        simple_module.session["simple_credentials"] = serialized
    else:
        simple_module.session.pop("simple_credentials", None)

    rp_id = simple_module.determine_rp_id()
    server = simple_module.create_fido_server(rp_id=rp_id)

    options, state = server.register_begin(
        simple_module.PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    simple_module.session["state"] = state
    simple_module.session["register_rp_id"] = rp_id

    options_dict = dict(options)
    options_dict["__session_state"] = simple_module.make_json_safe(state)
    public_key_options = options_dict.get("publicKey")
    if isinstance(public_key_options, MutableMapping):
        simple_module.session["simple_register_public_key"] = simple_module.make_json_safe(public_key_options)
    else:
        simple_module.session.pop("simple_register_public_key", None)

    if simple_module._SIMPLE_ALLOWED_ALGORITHMS:
        public_key_options = options_dict.get("publicKey")
        if isinstance(public_key_options, MutableMapping):
            params = public_key_options.get("pubKeyCredParams")
            allowed_params: List[Dict[str, Any]] = []
            existing_param_map: Dict[int, Dict[str, Any]] = {}
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, MutableMapping):
                        alg_value = param.get("alg")
                        if isinstance(alg_value, int) and alg_value in simple_module._SIMPLE_ALLOWED_ALGORITHMS:
                            cloned = dict(param)
                            cloned["type"] = "public-key"
                            existing_param_map[alg_value] = cloned
            for alg in simple_module._SIMPLE_ALLOWED_ALGORITHMS:
                if alg in existing_param_map:
                    allowed_params.append(existing_param_map[alg])
                else:
                    allowed_params.append({"type": "public-key", "alg": alg})
            public_key_options["pubKeyCredParams"] = allowed_params

    return simple_module.jsonify(simple_module.make_json_safe(options_dict))
