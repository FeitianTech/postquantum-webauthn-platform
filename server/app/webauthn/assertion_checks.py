"""What an assertion says beside what its credential's registration kept (WebAuthn L3
section 7.2), read one way for both tabs: its authenticator data and userHandle
(``assertion_parts``), and its backup flags (``backup_findings``). What a finding does --
refuse the sign-in, or report it -- is each tab's to say."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

from fido2.webauthn import AuthenticatorData

from . import client_binary
from .attestation import error_codes


class AssertionParts(NamedTuple):
    """An assertion's authenticator data and userHandle; each None when it is not there or does not read."""

    auth_data: AuthenticatorData | None
    user_handle: bytes | None


def assertion_parts(response: Any) -> AssertionParts:
    """The authenticator data and userHandle of an assertion as the browser's JSON writes it."""

    inner = response.get("response") if isinstance(response, Mapping) else None
    if not isinstance(inner, Mapping):
        return AssertionParts(None, None)
    try:
        # base64url: a standard-alphabet decode would drop '-' and '_' and misread the counter.
        auth_data: AuthenticatorData | None = AuthenticatorData(
            client_binary.decode_base64url_bytes(inner.get("authenticatorData"))
        )
    except Exception:
        auth_data = None
    return AssertionParts(auth_data, client_binary.decode_base64url_bytes(inner.get("userHandle")) or None)


def backup_findings(auth_data: AuthenticatorData, registered_backup_eligible: Any) -> tuple[list[str], list[str]]:
    """The errors and warnings of an assertion's backup flags.

    BS set without BE is an error. A BE that is not the one the registration kept
    (``registered_backup_eligible``; nothing is compared unless it is a bool) is a
    warning: L3 leaves what to do to the relying party's backup policy, and this one
    has none, so it says so and refuses nothing.
    """

    errors: list[str] = []
    warnings: list[str] = []
    eligible = auth_data.is_backup_eligible()
    if auth_data.is_backed_up() and not eligible:
        errors.append("backup_state_without_eligibility")
    if isinstance(registered_backup_eligible, bool) and eligible != registered_backup_eligible:
        warnings.append(error_codes.changed_backup_eligibility(registered_backup_eligible))
    return errors, warnings
