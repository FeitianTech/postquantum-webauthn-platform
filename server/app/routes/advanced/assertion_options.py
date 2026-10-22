"""Advanced authentication begin: the server, UV requirement and extensions fido2 is given.

The extension shaping here is authentication's own: largeBlob reads and writes
and PRF evaluation differ from registration's, so the two are kept apart.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.webauthn import UserVerificationRequirement

from ...config import relying_party
from ...webauthn import client_binary


def rp_id_refusal(public_key: Mapping[str, Any]) -> str | None:
    """Why the request may not use the RP ID it names (rpId, text by now); None when it may or names none."""

    if "rpId" not in public_key:
        return None
    return relying_party.requested_rp_id_refusal(public_key["rpId"], "rpId")


def assertion_server(public_key: Mapping[str, Any]) -> tuple[Any, str]:
    """A fido2 server for the RP ID the request names, else the configured or derived one, with the request's timeout."""

    rp_id = relying_party.determine_rp_id(public_key.get("rpId"))
    temp_server = relying_party.create_fido_server(rp_id=rp_id)

    # In milliseconds, as the options carry it (fido2 passes the server's timeout through).
    temp_server.timeout = public_key.get("timeout", 90000) or None
    return temp_server, rp_id


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
        return {"write": client_binary.read_request_field(ext_value["write"])}
    return ext_value


def _prf_inputs(inputs: Any) -> dict[str, Any]:
    """A PRF evaluation's first and second inputs, each read as bytes."""

    return {
        name: client_binary.read_request_field(inputs[name])
        for name in ("first", "second")
        if isinstance(inputs, Mapping) and name in inputs
    }


def _prf_extension(value: Any) -> Any:
    """PRF's eval and evalByCredential inputs as bytes; None for an eval with neither input."""

    if not (isinstance(value, dict) and ("eval" in value or "evalByCredential" in value)):
        return value
    processed: dict[str, Any] = {}
    if "eval" in value:
        evaluation = _prf_inputs(value["eval"])
        if evaluation:
            processed["eval"] = evaluation
    by_credential = value.get("evalByCredential")
    if isinstance(by_credential, Mapping):
        # Keyed by base64url credential ID, as the browser reads it.
        processed["evalByCredential"] = {
            credential_id: _prf_inputs(inputs) for credential_id, inputs in by_credential.items()
        }
    return processed or None


def process_assertion_extensions(extensions: Any) -> dict[str, Any]:
    processed_extensions = {}
    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            processed_extensions["largeBlob"] = _large_blob_extension(ext_value)
        elif ext_name == "prf":
            prf = _prf_extension(ext_value)
            if prf is not None:
                processed_extensions["prf"] = prf
        else:
            processed_extensions[ext_name] = ext_value
    return processed_extensions
