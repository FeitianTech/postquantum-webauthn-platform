from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from flask import jsonify, request, session

from fido2.cose import CoseKey
from fido2.webauthn import PublicKeyCredentialUserEntity

from ... import attestation, config
from ...challenge_registry import stamp_ceremony_state
from . import parsing

_SIMPLE_ALLOWED_ALGORITHMS: tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)

def register_begin_impl():
    payload = request.get_json(silent=True) or {}

    existing_credentials_raw: list[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, serialized = parsing._parse_client_credentials_impl(existing_credentials_raw)
    if serialized:
        session["simple_credentials"] = serialized
    else:
        session.pop("simple_credentials", None)

    rp_id = config.determine_rp_id()
    server = config.create_fido_server(rp_id=rp_id)

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["state"] = stamp_ceremony_state(dict(state))
    session["register_rp_id"] = rp_id

    options_dict = dict(options)
    # The ceremony state (and therefore the challenge) is deliberately NOT
    # returned to the client: the simple flow binds the challenge to the
    # server-side session only.
    public_key_options = options_dict.get("publicKey")
    if isinstance(public_key_options, MutableMapping):
        session["simple_register_public_key"] = attestation.make_json_safe(public_key_options)
    else:
        session.pop("simple_register_public_key", None)

    if _SIMPLE_ALLOWED_ALGORITHMS:
        public_key_options = options_dict.get("publicKey")
        if isinstance(public_key_options, MutableMapping):
            params = public_key_options.get("pubKeyCredParams")
            allowed_params: list[dict[str, Any]] = []
            existing_param_map: dict[int, dict[str, Any]] = {}
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, MutableMapping):
                        alg_value = param.get("alg")
                        if isinstance(alg_value, int) and alg_value in _SIMPLE_ALLOWED_ALGORITHMS:
                            cloned = dict(param)
                            cloned["type"] = "public-key"
                            existing_param_map[alg_value] = cloned
            for alg in _SIMPLE_ALLOWED_ALGORITHMS:
                if alg in existing_param_map:
                    allowed_params.append(existing_param_map[alg])
                else:
                    allowed_params.append({"type": "public-key", "alg": alg})
            public_key_options["pubKeyCredParams"] = allowed_params

    return jsonify(attestation.make_json_safe(options_dict))
