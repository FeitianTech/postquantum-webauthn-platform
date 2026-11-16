"""What an assertion says, read one way for both tabs: its authenticator data and its
userHandle (``assertion_parts``), each as the browser's JSON writes it."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

from fido2.webauthn import AuthenticatorData

from . import client_binary


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
