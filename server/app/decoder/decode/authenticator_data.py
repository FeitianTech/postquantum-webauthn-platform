"""Authenticator data (WebAuthn L3 section 6.1), read into its fields for the decoder.

The credential public key and the extensions inside it are read with the
decoder's own strict CBOR parser; a structure that does not fit raises
``_LocatedError`` with the offset and path where it stops fitting.
"""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AuthenticatorData

from ...webauthn.attestation import (
    encode_base64url,
    make_json_safe,
    summarize_authenticator_extensions,
)
from . import cbor_parser, pipeline


def _read_authenticator_data(data: bytes) -> dict[str, Any]:
    """Split authenticator data into its fields, or raise ``ValueError``.

    Accepts exactly what fido2's ``AuthenticatorData`` accepts -- a 37-byte
    header, the attested credential data its AT flag announces, the extensions
    its ED flag announces, and nothing after them -- but reads the credential
    public key and the extensions with the decoder's own strict CBOR parser.
    """

    if len(data) < 37:
        raise _LocatedError("authenticator data is shorter than its 37-byte header", len(data), "$")
    flags = data[32]
    fields: dict[str, Any] = {
        "rpIdHash": data[:32],
        "flags": flags,
        "counter": int.from_bytes(data[33:37], "big"),
    }
    offset = 37

    if flags & AuthenticatorData.FLAG.AT:
        if len(data) - offset < 18:
            raise _LocatedError("attested credential data is shorter than its 18-byte header", offset, "$")
        aaguid = data[offset : offset + 16]
        id_length = int.from_bytes(data[offset + 16 : offset + 18], "big")
        offset += 18
        if offset + id_length > len(data):
            raise _LocatedError(f"the credential ID declares {id_length} bytes; {len(data) - offset} remain", offset, "$")
        credential_id = data[offset : offset + id_length]
        key_offset = offset + id_length
        node, offset = _read_embedded_item(data, key_offset, "credentialPublicKey")
        public_key = cbor_parser._structure_to_value(node)
        if not isinstance(public_key, Mapping):
            raise _LocatedError("the credential public key is not a COSE_Key map", key_offset, "$<credentialPublicKey>")
        fields["attestedCredentialData"] = (aaguid, credential_id, public_key)

    if flags & AuthenticatorData.FLAG.ED:
        node, offset = _read_embedded_item(data, offset, "extensions")
        fields["extensions"] = cbor_parser._structure_to_value(node)

    if offset != len(data):
        raise _LocatedError(f"{len(data) - offset} byte(s) after what the AT and ED flags account for", offset, "$")
    return fields


class _LocatedError(ValueError):
    """Bytes that are well-formed CBOR, or none at all, but not the structure expected there."""

    def __init__(self, reason: str, offset: int, path: str) -> None:
        super().__init__(f"{reason} (offset {offset}, {path})")
        self.reason = reason
        self.offset = offset
        self.path = path


def _read_embedded_item(data: bytes, offset: int, name: str) -> tuple[dict[str, Any], int]:
    """Parse the CBOR item authData holds at ``offset``; an error names the item."""

    try:
        node, end, _ = cbor_parser.decode_item(data, offset)
    except cbor_parser._CborDecodingError as exc:
        raise cbor_parser._CborDecodingError(exc.reason, exc.offset, f"$<{name}>{exc.path[1:]}") from exc
    return node, end


def _describe_authenticator_data_bytes(data: bytes) -> dict[str, Any]:
    fields = _read_authenticator_data(data)
    flags = fields["flags"]

    flag_details = {
        "value": flags,
        "bitfield": f"0b{flags:08b}",
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
            "hex": fields["rpIdHash"].hex(),
            "base64url": encode_base64url(fields["rpIdHash"]),
        },
        "flags": flag_details,
        "signCount": fields["counter"],
    }

    credential_data = fields.get("attestedCredentialData")
    if credential_data is not None:
        aaguid, credential_id, public_key = credential_data
        details["attestedCredentialData"] = {
            "aaguid": str(uuid.UUID(bytes=aaguid)),
            "aaguidHex": aaguid.hex(),
            "credentialId": pipeline._binary_summary(credential_id, "binary"),
            "publicKey": make_json_safe(dict(public_key)),
        }

    if "extensions" in fields:
        extensions = fields["extensions"]
        extensions_payload: dict[str, Any] = {
            "raw": make_json_safe(extensions),
        }
        if isinstance(extensions, Mapping):
            extensions_payload["summary"] = make_json_safe(
                summarize_authenticator_extensions(extensions)
            )
        details["extensions"] = extensions_payload

    return details
