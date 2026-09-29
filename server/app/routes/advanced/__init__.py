"""Routes for the advanced JSON editor flows.

The implementation lives in this package's submodules; this module holds the
Flask rules. Import the submodule you need and patch there.
"""
from __future__ import annotations

from flask import Blueprint

from ...mds_provisioning import waits_for_the_snapshot
from . import artifacts, authentication, registration

# The HTTP rules, registered on the app by server.app.app.
bp = Blueprint("advanced", __name__)


@bp.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    return registration.advanced_register_begin()


@bp.route("/api/advanced/register/complete", methods=["POST"])
@waits_for_the_snapshot
def advanced_register_complete():
    return registration.advanced_register_complete()


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["GET"])
def api_get_advanced_credential_artifact(storage_id: str):
    return artifacts.api_get_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/credential-artifacts/bulk", methods=["POST"])
def api_get_advanced_credential_artifacts_bulk():
    return artifacts.api_get_advanced_credential_artifacts_bulk()


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["PUT"])
def api_put_advanced_credential_artifact(storage_id: str):
    return artifacts.api_put_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>/snapshot", methods=["PUT"])
def api_put_advanced_credential_snapshot(storage_id: str):
    return artifacts.api_put_advanced_credential_snapshot(storage_id)


@bp.route("/api/advanced/credential-artifacts/<string:storage_id>", methods=["DELETE"])
def api_delete_advanced_credential_artifact(storage_id: str):
    return artifacts.api_delete_advanced_credential_artifact(storage_id)


@bp.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    return authentication.advanced_authenticate_begin()


@bp.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    return authentication.advanced_authenticate_complete()
