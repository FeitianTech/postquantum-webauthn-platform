"""The Simple tab's account: the username a ceremony is for, and its user handle.

The username names the account's stored records, a file locally and an object on
Cloud Storage. So both begins refuse a name the store would refuse, before any
options are issued: once the authenticator has made a credential, nothing about
the name may fail. A username is the typed name trimmed as the page trims it,
then compared exactly: "Alice" and "alice" are two accounts, on the server as in
the browser (``tests/fixtures/simple-usernames.json`` holds both sides to it).
The user handle is what a registration gives the authenticator as ``user.id``:
one per account, which does not reveal the name.
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


# What JavaScript's String.prototype.trim removes, ECMA-262's WhiteSpace and LineTerminator: the
# page trims a typed username so (credentials/storage/local/simple-credentials.js), and so does this.
_TRIMMED = (
    "\t\n\v\f\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def read_username(value: Any) -> tuple[str | None, str | None]:
    """``value`` as a ceremony's username, trimmed as the page trims it; or the sentence that refuses it."""

    if not isinstance(value, str) or not value.strip(_TRIMMED):
        return None, USERNAME_REQUIRED
    trimmed = value.strip(_TRIMMED)
    try:
        username = storage_common.validate_storage_component(trimmed)
    except storage_common.InvalidStorageIdentifier:
        return None, USERNAME_RULES
    # The store trims again what Python counts as white space, which at an end of the name can only
    # be a control character JavaScript keeps (U+001C to U+001F, U+0085): refused, so the file the
    # store names is the name the page compares.
    if username != trimmed or len(username.encode("utf-8")) > USERNAME_MAX_BYTES:
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
