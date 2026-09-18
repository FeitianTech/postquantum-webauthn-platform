"""Client data and authenticator data description helpers for the decoder."""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from fido2 import cbor
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData

from ...attestation import (
    colon_hex,
    encode_base64url,
    make_json_safe,
    serialize_attestation_certificate,
    summarize_authenticator_extensions,
)
from ...encoding import encode_base64, try_decode_base64
from . import pipeline


def _describe_client_data_from_bytes(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8")
    parsed = json.loads(text)
    details = _build_client_data_details(parsed, raw_text=text)

    try:
        client_data = CollectedClientData(data)
    except Exception:
        return details

    challenge_info = details.get("challenge")
    if isinstance(challenge_info, dict):
        challenge_info.setdefault("base64url", encode_base64url(client_data.challenge))
        challenge_info.setdefault("hex", client_data.challenge.hex())

    details.setdefault("type", client_data.type)
    details["origin"] = client_data.origin
    details["crossOrigin"] = bool(client_data.cross_origin)

    return details


def _describe_authenticator_data_bytes(data: bytes) -> dict[str, Any]:
    auth_data = AuthenticatorData(data)
    flags = auth_data.flags

    flag_details = {
        "value": int(flags),
        "bitfield": f"0b{int(flags):08b}",
        "userPresent": bool(flags & AuthenticatorData.FLAG.UP),
        "userVerified": bool(flags & AuthenticatorData.FLAG.UV),
        "backupEligibility": bool(flags & AuthenticatorData.FLAG.BE),
        "backupState": bool(flags & AuthenticatorData.FLAG.BS),
        "attestedCredentialDataIncluded": bool(flags & AuthenticatorData.FLAG.AT),
        "extensionDataIncluded": bool(flags & AuthenticatorData.FLAG.ED),
        "flagsSet": [flag.name for flag in AuthenticatorData.FLAG if flags & flag],
    }

    details: dict[str, Any] = {
        "rpIdHash": {
            "hex": auth_data.rp_id_hash.hex(),
            "base64url": encode_base64url(auth_data.rp_id_hash),
        },
        "flags": flag_details,
        "signCount": auth_data.counter,
    }

    credential_data = auth_data.credential_data
    if credential_data is not None:
        details["attestedCredentialData"] = {
            "aaguid": str(credential_data.aaguid),
            "aaguidHex": credential_data.aaguid.hex(),
            "credentialId": _binary_summary(credential_data.credential_id, "binary"),
            "publicKey": make_json_safe(dict(credential_data.public_key)),
        }

    extensions = auth_data.extensions
    if extensions is not None:
        extensions_payload: dict[str, Any] = {
            "raw": make_json_safe(extensions),
        }
        if isinstance(extensions, Mapping):
            extensions_payload["summary"] = make_json_safe(
                summarize_authenticator_extensions(extensions)
            )
        details["extensions"] = extensions_payload

    return details


def _parse_attestation_object(data: bytes) -> dict[str, Any]:
    attestation = AttestationObject(data)
    details: dict[str, Any] = {
        "attestationFormat": attestation.fmt,
        "attestationStatement": make_json_safe(attestation.att_stmt),
        "authenticatorData": _describe_authenticator_data_bytes(bytes(attestation.auth_data)),
        "cbor": make_json_safe(cbor.decode(data)),
    }

    certificate_details = _extract_attestation_certificate(attestation.att_stmt)
    if certificate_details is not None:
        details["attestationCertificate"] = certificate_details

    return details


def _extract_attestation_certificate(att_stmt: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(att_stmt, Mapping):
        return None

    chain = att_stmt.get("x5c")
    if not isinstance(chain, Sequence) or not chain:
        return None

    first_entry = chain[0]
    cert_bytes: bytes | None

    if isinstance(first_entry, str):
        cert_bytes = try_decode_base64(first_entry)
    else:
        try:
            cert_bytes = bytes(first_entry)
        except Exception:
            cert_bytes = None

    if not cert_bytes:
        return None

    try:
        return serialize_attestation_certificate(cert_bytes)
    except Exception:
        return None


def _build_client_data_details(
    parsed: Mapping[str, Any], raw_text: str | None = None
) -> dict[str, Any]:
    details: dict[str, Any] = {}

    type_value = parsed.get("type")
    if type_value is not None:
        details["type"] = type_value

    challenge_value = parsed.get("challenge")
    if challenge_value is not None:
        challenge_info: dict[str, Any] = {"raw": challenge_value}
        if isinstance(challenge_value, str):
            try:
                challenge_bytes, challenge_encoding = pipeline._decode_binary_input(challenge_value)
            except ValueError:
                pass
            else:
                challenge_info.update(_binary_summary(challenge_bytes, challenge_encoding))
        details["challenge"] = challenge_info
    else:
        details["challenge"] = None

    origin_value = parsed.get("origin")
    if origin_value is not None:
        details["origin"] = origin_value

    cross_origin = parsed.get("crossOrigin")
    if cross_origin is not None:
        details["crossOrigin"] = bool(cross_origin)

    token_binding = parsed.get("tokenBinding")
    if token_binding is not None:
        details["tokenBinding"] = token_binding

    details["rawJson"] = parsed
    if raw_text is not None:
        details["rawText"] = raw_text

    return details


def _binary_summary(data: bytes, encoding: str | None = None) -> dict[str, Any]:
    summary = {
        "length": len(data),
        "base64": encode_base64(data),
        "base64url": encode_base64url(data),
        "hex": data.hex(),
        "colonHex": colon_hex(data),
    }
    if encoding:
        summary["encoding"] = encoding
    return summary


def _try_decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_public_key_credential(value: Mapping[str, Any]) -> bool:
    response = value.get("response")
    if not isinstance(response, Mapping):
        return False

    if not value.get("type") and not value.get("id"):
        return False

    return any(
        field in response
        for field in ("attestationObject", "clientDataJSON", "authenticatorData", "signature", "userHandle")
    )


def _is_client_data_dict(value: Mapping[str, Any]) -> bool:
    if not isinstance(value.get("type"), str):
        return False
    if "challenge" not in value:
        return False
    return isinstance(value.get("origin"), str)
