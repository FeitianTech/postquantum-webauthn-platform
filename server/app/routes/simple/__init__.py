"""Routes for the basic registration and authentication flows.

The implementation lives in this package's submodules; this module is the HTTP
face of it -- the Flask rules, plus re-exports of the pieces callers use. Each
submodule resolves its own names through its own imports, so a name here is the
same object the submodule defines -- patching one of these re-exports changes what
callers of *this package* see, not what the submodules call.
"""
from __future__ import annotations

from ...config import app
from .. import binary_helpers
from . import (
    authenticate_impl,
    binary,
    credential_parsing_impl,
    credentials_route_impl,
    register_begin_impl,
    register_complete_impl,
)

__all__ = [
    "_SIMPLE_ALLOWED_ALGORITHMS",
    "_add_base64_padding",
    "_decode_base64url_bytes",
    "_extract_assertion_credential_id",
    "_decode_binary_value",
    "_select_first",
    "_serialize_credential_for_session",
    "_parse_client_credentials",
    "register_begin",
    "register_complete",
    "authenticate_begin",
    "authenticate_complete",
    "list_credentials",
]

# The COSE algorithms the simple flow offers, filtered by what fido2 supports.
_SIMPLE_ALLOWED_ALGORITHMS = register_begin_impl._SIMPLE_ALLOWED_ALGORITHMS

# base64 padding and binary decode primitives.
_add_base64_padding = binary._add_base64_padding_impl
_decode_base64url_bytes = binary_helpers.decode_base64url_bytes
_decode_binary_value = binary._decode_binary_value_impl
_extract_assertion_credential_id = binary_helpers.extract_assertion_credential_id
_select_first = binary._select_first_impl

# Session-credential serialisation and parsing.
_parse_client_credentials = credential_parsing_impl._parse_client_credentials_impl
_serialize_credential_for_session = credential_parsing_impl._serialize_credential_for_session_impl


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    return register_begin_impl.register_begin_impl()


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    return register_complete_impl.register_complete_impl()


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    return authenticate_impl.authenticate_begin_impl()


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    return authenticate_impl.authenticate_complete_impl()


@app.route("/api/credentials", methods=["GET", "DELETE"])
def list_credentials():
    return credentials_route_impl.list_credentials_impl()
