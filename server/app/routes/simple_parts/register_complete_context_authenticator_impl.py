from __future__ import annotations

from typing import Any, Dict


def populate_authenticator_data_context_impl(simple_module: Any, ctx: Dict[str, Any]) -> None:
    try:
        auth_data_bytes = bytes(ctx["auth_data"])
    except Exception:
        auth_data_bytes = b""

    authenticator_data_raw = ""
    authenticator_data_hex = ""
    authenticator_data_hash = ""
    if auth_data_bytes:
        authenticator_data_raw = simple_module.base64.urlsafe_b64encode(auth_data_bytes).decode("utf-8").rstrip("=")
        authenticator_data_hex = auth_data_bytes.hex()
        authenticator_data_hash = simple_module.hashlib.sha256(auth_data_bytes).hexdigest()
        ctx["credential_info"]["authenticator_data_raw"] = authenticator_data_raw
        ctx["credential_info"]["authenticator_data_hex"] = authenticator_data_hex
        ctx["credential_info"]["authenticator_data_hash"] = authenticator_data_hash
        ctx["credential_properties"]["authenticatorDataHash"] = authenticator_data_hash

    algo = ctx["auth_data"].credential_data.public_key[3]
    if algo == -50:
        algoname = "ML-DSA-87 (PQC)"
    elif algo == -49:
        algoname = "ML-DSA-65 (PQC)"
    elif algo == -48:
        algoname = "ML-DSA-44 (PQC)"
    elif algo == -7:
        algoname = "ES256 (ECDSA)"
    elif algo == -257:
        algoname = "RS256 (RSA)"
    else:
        algoname = "Other (Classical)"

    flags_value = getattr(ctx["auth_data"], "flags", 0)
    flags_dict = {
        "UP": bool(flags_value & getattr(ctx["auth_data"].FLAG, "UP", 0)),
        "UV": bool(flags_value & getattr(ctx["auth_data"].FLAG, "UV", 0)),
        "BE": bool(flags_value & getattr(ctx["auth_data"].FLAG, "BE", 0)),
        "BS": bool(flags_value & getattr(ctx["auth_data"].FLAG, "BS", 0)),
        "AT": bool(flags_value & getattr(ctx["auth_data"].FLAG, "AT", 0)),
        "ED": bool(flags_value & getattr(ctx["auth_data"].FLAG, "ED", 0)),
    }

    rp_id_hash_bytes = getattr(ctx["auth_data"], "rp_id_hash", b"")
    if isinstance(rp_id_hash_bytes, (bytearray, memoryview)):
        rp_id_hash_bytes = bytes(rp_id_hash_bytes)
    elif not isinstance(rp_id_hash_bytes, bytes):
        rp_id_hash_bytes = b""

    rp_id_hash_hex = rp_id_hash_bytes.hex() if rp_id_hash_bytes else ""
    rp_id_hash_b64 = (
        simple_module.base64.urlsafe_b64encode(rp_id_hash_bytes).decode("ascii").rstrip("=")
        if rp_id_hash_bytes
        else ""
    )

    expected_rp_hash_bytes = simple_module.hashlib.sha256((ctx["resolved_rp_id"] or "").encode("utf-8")).digest()
    expected_rp_hash_hex = expected_rp_hash_bytes.hex()
    expected_rp_hash_b64 = simple_module.base64.urlsafe_b64encode(expected_rp_hash_bytes).decode("ascii").rstrip("=")

    if ctx["attestation_rp_id_hash_valid"] is None:
        ctx["attestation_rp_id_hash_valid"] = rp_id_hash_bytes == expected_rp_hash_bytes

    if rp_id_hash_hex:
        ctx["credential_properties"]["rpIdHash"] = rp_id_hash_hex
    if rp_id_hash_b64:
        ctx["credential_properties"]["rpIdHashBase64"] = rp_id_hash_b64
    ctx["credential_properties"]["rpIdHashExpected"] = expected_rp_hash_hex
    ctx["credential_properties"]["rpIdHashExpectedBase64"] = expected_rp_hash_b64

    ctx["authenticator_data_raw"] = authenticator_data_raw
    ctx["authenticator_data_hex"] = authenticator_data_hex
    ctx["authenticator_data_hash"] = authenticator_data_hash
    ctx["algo"] = algo
    ctx["algoname"] = algoname
    ctx["flags_value"] = flags_value
    ctx["flags_dict"] = flags_dict
    ctx["rp_id_hash_bytes"] = rp_id_hash_bytes
    ctx["rp_id_hash_hex"] = rp_id_hash_hex
    ctx["rp_id_hash_b64"] = rp_id_hash_b64
    ctx["expected_rp_hash_bytes"] = expected_rp_hash_bytes
    ctx["expected_rp_hash_hex"] = expected_rp_hash_hex
    ctx["expected_rp_hash_b64"] = expected_rp_hash_b64
