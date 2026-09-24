"""Advanced authentication begin: the server, UV requirement and extensions fido2 is given.

The extension shaping here is authentication's own: largeBlob reads and writes
and PRF evaluation differ from registration's, so the two are kept apart.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import session

from fido2.webauthn import UserVerificationRequirement

from ... import config
from . import binary


def assertion_server(public_key: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    """A fido2 server for the RP of the last registration begin, with the request's timeout."""

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
    return temp_server, resolved_rp_id, stored_rp_name


def user_verification_requirement(public_key: Mapping[str, Any]) -> UserVerificationRequirement:
    user_verification = public_key.get("userVerification", "preferred")
    if user_verification == "required":
        return UserVerificationRequirement.REQUIRED
    if user_verification == "discouraged":
        return UserVerificationRequirement.DISCOURAGED
    return UserVerificationRequirement.PREFERRED


def _large_blob_extension(ext_value: Any) -> Any:
    if not isinstance(ext_value, dict):
        return ext_value
    if ext_value.get("read"):
        return {"read": True}
    if ext_value.get("write"):
        return {"write": binary._decode_request_binary(ext_value["write"])}
    return ext_value


def process_assertion_extensions(extensions: Any) -> dict[str, Any]:
    processed_extensions = {}
    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            processed_extensions["largeBlob"] = _large_blob_extension(ext_value)
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if "first" in prf_eval:
                    processed_eval["first"] = binary._decode_request_binary(prf_eval["first"])
                if "second" in prf_eval:
                    processed_eval["second"] = binary._decode_request_binary(prf_eval["second"])
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value
    return processed_extensions
