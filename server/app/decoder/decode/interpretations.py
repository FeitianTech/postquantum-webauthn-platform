"""What the decoder adds beside a decoded value: extensions and attestation, interpreted.

Each ``for_*`` function returns two things: the ``extraData`` of a decoder
result -- keys the response puts into ``data`` next to the decoded value,
never in place of any of it -- and the findings about what is inside the
byte strings it read (authData, certInfo, pubArea), located in the input. A
value with nothing to interpret adds nothing.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fido2.webauthn import AuthenticatorData

from . import attestation_statement, authenticator_data_findings, extensions
from .keys import MISSING, get_mapping_entry

_AUTH_DATA_LOCATION = "authenticator data extensions (ED flag)"
_UNSIGNED_LOCATION = "unsignedExtensionOutputs"

Interpretation = tuple[dict[str, Any], list[dict[str, Any]]]


def for_ctap(classification: str, value: Any, node: Mapping[str, Any], data: bytes) -> Interpretation:
    """A CTAP request or response: its extensions, authData and attestation statement."""

    extra: dict[str, Any] = {}
    blocks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if classification == "other" and _looks_like_attestation_object(value):
        # Text keys are a WebAuthn attestation object's (L3 section 6.5.4), never
        # CTAP members; one that did not read as one (its authData does not
        # parse) is still interpreted as what it is.
        return for_attestation_object(value, node, data)
    if classification == "make_credential_input":
        _add(blocks, get_mapping_entry(value, 6), extensions.MAKE_CREDENTIAL_INPUT, "extensions (0x06)", "${6}")
    elif classification == "get_assertion_input":
        _add(blocks, get_mapping_entry(value, 4), extensions.GET_ASSERTION_INPUT, "extensions (0x04)", "${4}")
    elif classification in ("make_credential_output", "get_assertion_output"):
        registration = classification == "make_credential_output"
        findings += authenticator_data_findings.for_member(node, data, (2,))
        key, auth_data = _member(value, (2,))
        output = extensions.MAKE_CREDENTIAL_OUTPUT if registration else extensions.GET_ASSERTION_OUTPUT
        _add_auth_data(blocks, auth_data, output, _path(key))
        unsigned_key = 6 if registration else 8
        unsigned = extensions.MAKE_CREDENTIAL_UNSIGNED if registration else extensions.GET_ASSERTION_UNSIGNED
        _add(
            blocks,
            get_mapping_entry(value, unsigned_key),
            unsigned,
            f"{_UNSIGNED_LOCATION} (0x{unsigned_key:02x})",
            f"${{{unsigned_key}}}",
        )
        if registration:
            _, fmt = _member(value, (1,))
            _, att_stmt = _member(value, (3,))
            findings += _attestation(extra, fmt, att_stmt, auth_data, node, data, (3,))
    _extensions(extra, blocks)
    return extra, findings


def for_attestation_object(value: Mapping[Any, Any], node: Mapping[str, Any], data: bytes) -> Interpretation:
    extra: dict[str, Any] = {}
    blocks: list[dict[str, Any]] = []
    findings = authenticator_data_findings.for_member(node, data, ("authData",))
    auth_data = value.get("authData")
    _add_auth_data(blocks, auth_data, extensions.MAKE_CREDENTIAL_OUTPUT, '${"authData"}')
    findings += _attestation(extra, value.get("fmt"), value.get("attStmt"), auth_data, node, data, ("attStmt",))
    _extensions(extra, blocks)
    return extra, findings


def for_authenticator_data(data: bytes) -> Interpretation:
    """Bare authData: the AT flag is the only sign of which ceremony made it."""

    blocks: list[dict[str, Any]] = []
    if len(data) > 32 and data[32] & AuthenticatorData.FLAG.AT:
        role, basis = extensions.MAKE_CREDENTIAL_OUTPUT, "read as a registration's: the AT flag is set"
    else:
        role, basis = extensions.GET_ASSERTION_OUTPUT, "read as an assertion's: the AT flag is clear"
    _add_auth_data(blocks, data, role, "$", basis=basis)
    extra: dict[str, Any] = {}
    _extensions(extra, blocks)
    return extra, authenticator_data_findings.check(data, 0, "$")


def for_public_key_credential(
    credential: Mapping[str, Any],
    attestation_object: tuple[Mapping[Any, Any], Mapping[str, Any], bytes] | None,
    authenticator_data: bytes | None,
) -> Interpretation:
    """The binary fields of a PublicKeyCredential; findings name the field they are in."""

    extra: dict[str, Any] = {}
    blocks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if attestation_object is not None:
        value, node, data = attestation_object
        source = "response.attestationObject"
        _add_auth_data(blocks, value.get("authData"), extensions.MAKE_CREDENTIAL_OUTPUT, '${"authData"}', source=source)
        located = _attestation(extra, value.get("fmt"), value.get("attStmt"), value.get("authData"), node, data, ("attStmt",))
        findings += [{**finding, "source": source} for finding in located]
    if authenticator_data is not None:
        _add_auth_data(
            blocks, authenticator_data, extensions.GET_ASSERTION_OUTPUT, "$", source="response.authenticatorData"
        )
    results = credential.get("clientExtensionResults", MISSING)
    if results is MISSING:
        results = credential.get("getClientExtensionResults", MISSING)
    if results is not MISSING:
        _add(blocks, results, extensions.CLIENT_OUTPUT, "clientExtensionResults", "clientExtensionResults")
    _extensions(extra, blocks)
    return extra, findings


def _looks_like_attestation_object(value: Any) -> bool:
    return (
        isinstance(get_mapping_entry(value, "fmt"), str)
        and isinstance(get_mapping_entry(value, "authData"), bytes)
        and get_mapping_entry(value, "attStmt") is not MISSING
    )


def _member(value: Any, keys: Sequence[Any]) -> tuple[Any, Any]:
    for key in keys:
        entry = get_mapping_entry(value, key)
        if entry is not MISSING:
            return key, entry
    return keys[0], None


def _path(key: Any) -> str:
    return f'${{"{key}"}}' if isinstance(key, str) else f"${{{key}}}"


def _attestation(
    extra: dict[str, Any],
    fmt: Any,
    att_stmt: Any,
    auth_data: Any,
    node: Mapping[str, Any],
    data: bytes,
    att_stmt_keys: Sequence[Any],
) -> list[dict[str, Any]]:
    """Interpret the statement into ``extra``; return its TPM errors, located in the input."""

    if fmt is None:
        return []
    view = attestation_statement.interpret(fmt, att_stmt, auth_data)
    extra["attestationStatementDecoded"] = view
    findings: list[dict[str, Any]] = []
    statement_node = authenticator_data_findings.member_node(node, att_stmt_keys)
    for name in ("certInfo", "pubArea"):
        error = (view.get("fields") or {}).get(name, {}).get("error") if isinstance(view.get("fields"), Mapping) else None
        member = authenticator_data_findings.member_node(statement_node, (name,)) if statement_node else None
        if not isinstance(error, Mapping) or member is None or member.get("indefinite"):
            continue
        start = member["end"] - member["length"]
        findings.append(
            {
                "code": "tpm-structure",
                "category": "attestation",
                "offset": start + error["offset"],
                "path": member["path"],
                "message": error["message"],
            }
        )
    return findings


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
    if found is MISSING or found == {}:
        return
    blocks.append(extensions.block(found, role=role, location=_AUTH_DATA_LOCATION, path=f"{path}<extensions>", basis=basis))
    if source:
        blocks[-1]["source"] = source


def _add(blocks: list[dict[str, Any]], value: Any, role: str, location: str, path: str) -> None:
    # An empty map has nothing to interpret, so it adds nothing.
    if value is None or value is MISSING or value == {}:
        return
    blocks.append(extensions.block(value, role=role, location=location, path=path))


def _extensions(extra: dict[str, Any], blocks: list[dict[str, Any]]) -> None:
    if blocks:
        extra["extensionsDecoded"] = blocks
