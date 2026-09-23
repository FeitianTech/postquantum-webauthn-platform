"""Configuration and setup for the demo server's Flask application.

The implementation lives in this package's submodules; this module is the public
face of it and re-exports the pieces callers use. Each submodule resolves its own
names through its own imports, so a name here is the same object the submodule
defines -- patching one of these re-exports changes what callers of *this module*
see (the routes reach ``create_fido_server`` and ``determine_rp_id`` through it),
not what the submodules call.

Importing the package configures the one Flask ``app``:

- ``paths``: the project, frontend and runtime locations, and ``basepath``.
- ``application``: the Flask singleton itself.
- ``session_secret``: the session secret. Resolved on import, and may write
  ``<instance_path>/session-secret.key``.
- ``compression``: the gzip ``after_request`` handler.
- ``proxy``: ``ProxyFix`` when the forwarded headers are trusted (never
  ``X-Forwarded-Host``).
- ``session_cookie``: the session cookie's flags and lifetime.
- ``security_headers``: CSP, Permissions-Policy, HSTS and friends. Its
  ``after_request`` handler is registered after ``compression``'s, and Flask runs
  them in reverse, so the headers are set before the body is compressed.
- ``origins``: the exact-origin allowlist and the origin helpers.
- ``attestation_trust``: operator-trusted attestation CAs.
- ``mds``: where the MDS snapshot and the session metadata live.
- ``relying_party``: the RP ID and name, and ``create_fido_server``.

The MDS trust anchors live in ``server.app.mds_trust``, outside this package, so
the snapshot updater can import them without building the app.
"""
from __future__ import annotations

from ..env_flags import parse_env_flag
from ..mds_trust import (
    FIDO_METADATA_TRUST_ROOT_CERT,
)
from . import (
    application,
    attestation_trust,
    compression,
    mds,
    origins,
    paths,
    proxy,
    relying_party,
    security_headers,
    session_cookie,
    session_secret,
)

__all__ = [
    "app",
    "basepath",
    "build_rp_entity",
    "set_security_headers",
    "create_fido_server",
    "determine_expected_origin",
    "determine_rp_id",
    "extract_client_data_origin",
    "get_allowed_origins",
    "is_origin_allowed",
    "normalise_origin",
    "warn_if_development_rp_configuration",
    "MDS_METADATA_CACHE_PATH",
    "MDS_EXPLORER_META_PATH",
    "MDS_EXPLORER_PATH",
    "MDS_METADATA_FILENAME",
    "MDS_METADATA_PATH",
    "MDS_METADATA_VERIFIED_PATH",
    "MDS_METADATA_URL",
    "SESSION_METADATA_DIR",
    "FIDO_METADATA_TRUST_ROOT_CERT",
]

# The Flask application.
app = application.app

# Imported for what importing them does to ``app``; nothing is re-exported.
_APP_CONFIGURING_MODULES = (
    attestation_trust,
    compression,
    proxy,
    session_cookie,
    session_secret,
)

# Filesystem locations. The three private roots are imported by static_assets,
# mds_provisioning and credential_artifacts.
_FRONTEND_ROOT = paths._FRONTEND_ROOT
_FRONTEND_STATIC_ROOT = paths._FRONTEND_STATIC_ROOT
_SERVER_RUNTIME_ROOT = paths._SERVER_RUNTIME_ROOT
basepath = paths.basepath
MDS_EXPLORER_FULL_PATH = mds.MDS_EXPLORER_FULL_PATH
MDS_EXPLORER_META_PATH = mds.MDS_EXPLORER_META_PATH
MDS_EXPLORER_PATH = mds.MDS_EXPLORER_PATH
MDS_METADATA_CACHE_PATH = mds.MDS_METADATA_CACHE_PATH
MDS_METADATA_FILENAME = mds.MDS_METADATA_FILENAME
MDS_METADATA_PATH = mds.MDS_METADATA_PATH
MDS_METADATA_URL = mds.MDS_METADATA_URL
MDS_METADATA_VERIFIED_PATH = mds.MDS_METADATA_VERIFIED_PATH
SESSION_METADATA_DIR = mds.SESSION_METADATA_DIR

# The relying party.
build_rp_entity = relying_party.build_rp_entity
create_fido_server = relying_party.create_fido_server
determine_rp_id = relying_party.determine_rp_id
warn_if_development_rp_configuration = relying_party.warn_if_development_rp_configuration

# The origin policy.
determine_expected_origin = origins.determine_expected_origin
extract_client_data_origin = origins.extract_client_data_origin
get_allowed_origins = origins.get_allowed_origins
is_origin_allowed = origins.is_origin_allowed
normalise_origin = origins.normalise_origin

# Response security headers.
set_security_headers = security_headers.set_security_headers

# Kept for its importers; the submodules call ``parse_env_flag`` directly.
_env_flag = parse_env_flag
