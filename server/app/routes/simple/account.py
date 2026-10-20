"""The Simple tab's account: the username a ceremony is for, and its user handle.

The username names the account's stored records, a file locally and an object on
Cloud Storage. So both begins refuse a name the store would refuse, before any
options are issued: once the authenticator has made a credential, nothing about
the name may fail. The user handle is what a registration gives the
authenticator as ``user.id``: one per account, which does not reveal the name.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from flask import current_app

from ...storage import common as storage_common

# Authenticators keep at most 64 bytes of user.name (CTAP 2.1), and the store's
# longest local file name, ``<name>_credential_data.json.tmp.<12 hex>``, leaves
# room for 217.
USERNAME_MAX_BYTES = 64

USERNAME_REQUIRED = "Please enter a username."
USERNAME_RULES = (
    f"A username is at most {USERNAME_MAX_BYTES} bytes long, does not start with a dot, "
    "and has no slash, backslash, control character or two dots in a row."
)


def read_username(value: Any) -> tuple[str | None, str | None]:
    """``value`` as a ceremony's username, trimmed as the store trims it; or the sentence that refuses it."""

    if not isinstance(value, str) or not value.strip():
        return None, USERNAME_REQUIRED
    try:
        username = storage_common.validate_storage_component(value)
    except storage_common.InvalidStorageIdentifier:
        return None, USERNAME_RULES
    if len(username.encode("utf-8")) > USERNAME_MAX_BYTES:
        return None, USERNAME_RULES
    return username, None


# What the user handle's HMAC is for, so the app's secret keys it apart from
# anything else it signs.
_USER_HANDLE_LABEL = b"simple-user-handle\x00"


def user_handle(namespace: str, username: str) -> bytes:
    """The user handle of ``username``'s account in ``namespace``: 32 bytes that name neither.

    An HMAC-SHA256 of both under the app's secret. The account gets the same one
    at every registration, another account (another name, or the same name in
    another visitor's namespace) another one, and without the secret nobody can
    tell the name from it.
    """

    secret = current_app.secret_key
    key = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    message = _USER_HANDLE_LABEL + namespace.encode("utf-8") + b"\x00" + username.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).digest()
