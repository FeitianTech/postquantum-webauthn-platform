"""What a verified registration's authenticator data and extension outputs say, one way for both tabs.

The flags in the order of their bits (``flags``), whether largeBlob did anything
(``large_blob_result``), a byte string's three spellings (``byte_forms``), the
AAGUID (``aaguid_values``, ``record_aaguid``, ``aaguid_block``), authData's
rpIdHash beside the hash of the RP ID it should be (``rp_id_hash_report``,
``record_rp_id_hash``), the relying party's view of the registration
(``relying_party_info``, ``registration_data``), and the credential record the
browser keeps (``stored_credential``): each in one key order for both tabs.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from .. import aaguid, json_values
from ..encoding import encode_base64, encode_base64url

# authData's flags, in the order of their bits (WebAuthn L3 section 6.1).
FLAG_NAMES = ("UP", "UV", "BE", "BS", "AT", "ED")

# The fields of the credential record the browser keeps, in their order; each tab gives the ones it has.
STORED_CREDENTIAL_KEYS = (
    "type",
    "email",
    "userName",
    "displayName",
    "residentKey",
    "largeBlob",
    "authenticatorAttachment",
    "credentialId",
    "credentialIdBase64Url",
    "credentialIdHex",
    "aaguid",
    "aaguidHex",
    "aaguidGuid",
    "publicKeyAlgorithm",
    "publicKey",
    "publicKeyBase64",
    "publicKeyBase64Url",
    "publicKeyBytes",
    "publicKeyCose",
    "publicKeyType",
    "signCount",
    "createdAt",
    "clientExtensionOutputs",
    "attestationFormat",
    "attestationStatement",
    "attestationObject",
    "authenticatorData",
    "authenticatorDataHex",
    "authenticatorDataHash",
    "clientDataJSON",
    "relyingParty",
    "properties",
    "registrationResponse",
    "userHandle",
    "userHandleBase64",
    "userHandleBase64Url",
    "userHandleHex",
)


def flags(auth_data: Any) -> dict[str, bool]:
    flags_value = getattr(auth_data, "flags", 0)
    return {flag: bool(flags_value & getattr(auth_data.FLAG, flag, 0)) for flag in FLAG_NAMES}


def large_blob_result(client_extension_results: Any) -> bool:
    """Whether the largeBlob output says the authenticator supported, wrote or read a blob."""

    if not isinstance(client_extension_results, Mapping) or "largeBlob" not in client_extension_results:
        return False
    large_blob_value = client_extension_results.get("largeBlob")
    if isinstance(large_blob_value, Mapping):
        return bool(
            large_blob_value.get("supported")
            or large_blob_value.get("written")
            or large_blob_value.get("blob")
            or large_blob_value.get("result")
        )
    return bool(large_blob_value)


def byte_forms(value: bytes) -> dict[str, str]:
    """``value`` as base64, base64url and hex."""

    return {
        "base64": encode_base64(value),
        "base64url": encode_base64url(value),
        "hex": value.hex(),
    }


def aaguid_values(credential_data: Any) -> tuple[bytes | None, str | None, str | None]:
    """The AAGUID's bytes, hex and GUID spelling; hex and GUID only for 16 bytes."""

    aaguid_hex = None
    aaguid_guid = None
    aaguid_bytes: bytes | None = None
    aaguid_value = getattr(credential_data, "aaguid", None)
    if aaguid_value is not None:
        try:
            aaguid_bytes = bytes(aaguid_value)
        except (TypeError, ValueError):
            aaguid_bytes = None
        if aaguid_bytes is not None and len(aaguid_bytes) == 16:
            aaguid_hex = aaguid_bytes.hex()
            aaguid_guid = aaguid.guid(aaguid_bytes)
    return aaguid_bytes, aaguid_hex, aaguid_guid


def record_aaguid(properties: dict[str, Any], aaguid_hex: str | None, aaguid_guid: str | None) -> None:
    """Add the AAGUID to a stored credential's properties."""

    if aaguid_hex:
        properties["aaguid"] = aaguid_hex
        properties["aaguidHex"] = aaguid_hex
    if aaguid_guid:
        properties["aaguidGuid"] = aaguid_guid


def aaguid_block(aaguid_hex: str | None, aaguid_guid: str | None) -> dict[str, Any]:
    """The AAGUID as the relying party's view shows it."""

    return {"raw": aaguid_hex, "guid": aaguid_guid}


def rp_id_hash_report(auth_data: Any, resolved_rp_id: str) -> dict[str, Any]:
    """authData's rpIdHash and the hash of the RP ID it should be, as bytes, hex and base64url."""

    rp_id_hash_hex = ""
    rp_id_hash_b64 = ""
    try:
        rp_id_hash_bytes = bytes(getattr(auth_data, "rp_id_hash", b""))
    except (TypeError, ValueError):
        rp_id_hash_bytes = b""
    else:
        rp_id_hash_hex = rp_id_hash_bytes.hex()
        rp_id_hash_b64 = encode_base64url(rp_id_hash_bytes)

    expected_rp_hash_bytes = hashlib.sha256((resolved_rp_id or "").encode("utf-8")).digest()
    return {
        "bytes": rp_id_hash_bytes,
        "hex": rp_id_hash_hex,
        "base64url": rp_id_hash_b64,
        "expectedBytes": expected_rp_hash_bytes,
        "expectedHex": expected_rp_hash_bytes.hex(),
        "expectedBase64url": encode_base64url(expected_rp_hash_bytes),
    }


def record_rp_id_hash(properties: dict[str, Any], report: Mapping[str, Any]) -> None:
    """Add the rpIdHash and the expected one to a stored credential's properties."""

    if report["hex"]:
        properties["rpIdHash"] = report["hex"]
    if report["base64url"]:
        properties["rpIdHashBase64"] = report["base64url"]
    properties["rpIdHashExpected"] = report["expectedHex"]
    properties["rpIdHashExpectedBase64"] = report["expectedBase64url"]


def registration_data(
    *,
    authenticator_data: tuple[str, str],
    client_extension_results: Any,
    flags: dict[str, bool],
    signature_counter: Any,
    attestation_checks: Any,
    attestation_summary: Any,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """What the registration sent and what its checks found; ``authenticator_data`` is its hex and SHA-256."""

    authenticator_data_hex, authenticator_data_hash = authenticator_data
    data: dict[str, Any] = {
        "authenticatorData": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash,
        "clientExtensionResults": json_values.make_json_safe(client_extension_results),
        "flags": flags,
        "signatureCounter": signature_counter,
        "attestationChecks": attestation_checks,
        "attestationSummary": attestation_summary,
    }
    if warnings:
        data["warnings"] = warnings
    return data


def relying_party_info(
    *,
    aaguid: dict[str, Any] | None,
    attestation_format: Any,
    created_at: str,
    credential_id: Mapping[str, Any],
    rp_hash: Mapping[str, Any],
    rp_id_hash_match: bool,
    authenticator_data_hash: str,
    large_blob: bool,
    public_key_algorithm: Any,
    registration: dict[str, Any],
    user_handle: bytes,
    attestation_object: Any = None,
    device: dict[str, Any] | None = None,
    resident_key: bool | None = None,
    attestation_certificate: Any = None,
    attestation_certificates: Any = None,
) -> dict[str, Any]:
    """The relying party's view of the registration, as the answer reports it and the record keeps it.

    ``credential_id`` holds its ``hex``, ``base64`` and ``base64url``. What only
    one tab reports is left out when not given: the AAGUID block and the
    attestation object, the device, the resident-key result, and the
    attestation certificates.
    """

    rp_info: dict[str, Any] = {}
    if aaguid is not None:
        rp_info["aaguid"] = aaguid
    rp_info["attestationFmt"] = attestation_format
    if attestation_object is not None:
        rp_info["attestationObject"] = attestation_object
    rp_info.update(
        {
            "createdAt": created_at,
            "credentialId": credential_id["hex"],
            "credentialIdBase64": credential_id["base64"],
            "credentialIdBase64Url": credential_id["base64url"],
            "rpIdHash": rp_hash["hex"],
            "rpIdHashBase64": rp_hash["base64url"],
            "rpIdHashExpected": rp_hash["expectedHex"],
            "rpIdHashExpectedBase64": rp_hash["expectedBase64url"],
            "rpIdHashMatch": rp_id_hash_match,
            "authenticatorDataHash": authenticator_data_hash,
        }
    )
    if device is not None:
        rp_info["device"] = device
    rp_info["largeBlob"] = large_blob
    rp_info["publicKeyAlgorithm"] = public_key_algorithm
    rp_info["registrationData"] = registration
    if resident_key is not None:
        rp_info["residentKey"] = resident_key
    rp_info["userHandle"] = byte_forms(user_handle)
    if attestation_certificate:
        rp_info["attestationCertificate"] = attestation_certificate
    if attestation_certificates:
        rp_info["attestationCertificates"] = attestation_certificates
    return rp_info


def stored_credential(fields: Mapping[str, Any], *, drop_none: bool = False) -> dict[str, Any]:
    """The credential record the browser keeps: ``fields`` in ``STORED_CREDENTIAL_KEYS``' order.

    The Simple tab keeps a field that is null; the Advanced tab leaves it out (``drop_none``).
    """

    unknown = set(fields) - set(STORED_CREDENTIAL_KEYS)
    if unknown:
        raise ValueError(f"not a stored credential field: {sorted(unknown)}")
    return {
        key: fields[key]
        for key in STORED_CREDENTIAL_KEYS
        if key in fields and not (drop_none and fields[key] is None)
    }
