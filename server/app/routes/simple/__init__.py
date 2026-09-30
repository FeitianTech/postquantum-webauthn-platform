"""Routes for the basic registration and authentication flows.

The implementation lives in this package's submodules; this module holds the
Flask rules. Import the submodule you need and patch there.
"""
from __future__ import annotations

from flask import Blueprint

from ...mds_provisioning import waits_for_the_snapshot
from . import authentication, registration

# The HTTP rules, registered on the app by server.app.app.
bp = Blueprint("simple", __name__)


@bp.route("/api/register/begin", methods=["POST"])
def register_begin():
    return registration.register_begin()


@bp.route("/api/register/complete", methods=["POST"])
@waits_for_the_snapshot
def register_complete():
    return registration.register_complete()


@bp.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    return authentication.authenticate_begin()


@bp.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    return authentication.authenticate_complete()
