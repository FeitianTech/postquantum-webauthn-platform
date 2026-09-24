"""What the decoder adds beside a decoded value: its extensions, interpreted.

Each function returns the ``extraData`` of a decoder result: keys the response
puts into ``data`` next to the decoded value, never in place of any of it. A
value with nothing to interpret adds nothing.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AuthenticatorData

from . import authenticator_data_findings, extensions
from .keys import MISSING, get_mapping_entry

_AUTH_DATA_LOCATION = "authenticator data extensions (ED flag)"
_UNSIGNED_LOCATION = "unsignedExtensionOutputs"


def for_ctap(classification: str, value: Any) -> dict[str, Any]:
    """Extensions in a CTAP request or response."""

    blocks: list[dict[str, Any]] = []
    if classification == "make_credential_input":
        _add(blocks, get_mapping_entry(value, 6), extensions.MAKE_CREDENTIAL_INPUT, "extensions (0x06)", "${6}")
    elif classification == "get_assertion_input":
        _add(blocks, get_mapping_entry(value, 4), extensions.GET_ASSERTION_INPUT, "extensions (0x04)", "${4}")
    elif classification in ("make_credential_output", "get_assertion_output"):
        registration = classification == "make_credential_output"
        key, auth_data = _auth_data_member(value)
        path = f'${{"{key}"}}' if isinstance(key, str) else f"${{{key}}}"
        output = extensions.MAKE_CREDENTIAL_OUTPUT if registration else extensions.GET_ASSERTION_OUTPUT
        _add_auth_data(blocks, auth_data, output, path)
        unsigned_key = 6 if registration else 8
        unsigned = extensions.MAKE_CREDENTIAL_UNSIGNED if registration else extensions.GET_ASSERTION_UNSIGNED
        _add(
            blocks,
            get_mapping_entry(value, unsigned_key),
            unsigned,
            f"{_UNSIGNED_LOCATION} (0x{unsigned_key:02x})",
            f"${{{unsigned_key}}}",
        )
    return _extra(blocks)


def for_attestation_object(value: Mapping[Any, Any]) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    _add_auth_data(blocks, value.get("authData"), extensions.MAKE_CREDENTIAL_OUTPUT, '${"authData"}')
    return _extra(blocks)


def for_authenticator_data(data: bytes) -> dict[str, Any]:
    """Bare authData: the AT flag is the only sign of which ceremony made it."""

    blocks: list[dict[str, Any]] = []
    if len(data) > 32 and data[32] & AuthenticatorData.FLAG.AT:
        role, basis = extensions.MAKE_CREDENTIAL_OUTPUT, "read as a registration's: the AT flag is set"
    else:
        role, basis = extensions.GET_ASSERTION_OUTPUT, "read as an assertion's: the AT flag is clear"
    _add_auth_data(blocks, data, role, "$", basis=basis)
    return _extra(blocks)


def for_public_key_credential(
    credential: Mapping[str, Any],
    attestation_object: Mapping[Any, Any] | None,
    authenticator_data: bytes | None,
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    if attestation_object is not None:
        _add_auth_data(
            blocks,
            attestation_object.get("authData"),
            extensions.MAKE_CREDENTIAL_OUTPUT,
            '${"authData"}',
            source="response.attestationObject",
        )
    if authenticator_data is not None:
        _add_auth_data(
            blocks, authenticator_data, extensions.GET_ASSERTION_OUTPUT, "$", source="response.authenticatorData"
        )
    results = credential.get("clientExtensionResults", MISSING)
    if results is MISSING:
        results = credential.get("getClientExtensionResults", MISSING)
    _add(blocks, None if results is MISSING else results, extensions.CLIENT_OUTPUT, "clientExtensionResults", "clientExtensionResults")
    return _extra(blocks)


def _auth_data_member(value: Mapping[Any, Any]) -> tuple[Any, Any]:
    for key in (2, "authData"):
        entry = get_mapping_entry(value, key)
        if entry is not MISSING:
            return key, entry
    return 2, None


def _add_auth_data(
    blocks: list[dict[str, Any]],
    auth_data: Any,
    role: str,
    path: str,
    *,
    basis: str | None = None,
    source: str | None = None,
) -> None:
    if not isinstance(auth_data, bytes):
        return
    found = authenticator_data_findings.extensions(auth_data)
    if found is MISSING:
        return
    blocks.append(extensions.block(found, role=role, location=_AUTH_DATA_LOCATION, path=f"{path}<extensions>", basis=basis))
    if source:
        blocks[-1]["source"] = source


def _add(blocks: list[dict[str, Any]], value: Any, role: str, location: str, path: str) -> None:
    if value is None or value is MISSING:
        return
    blocks.append(extensions.block(value, role=role, location=location, path=path))


def _extra(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    return {"extensionsDecoded": blocks} if blocks else {}
