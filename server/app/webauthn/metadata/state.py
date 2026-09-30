"""The settings the metadata modules share.

A leaf: it imports nothing from ``server.app``, so any module here can depend on
it. The snapshot's caches are ``server.app.mds.cache.CACHE``; the visitor
session's settings and cleanup are ``server.app.visitor_session``'s.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_METADATA_REPO_FOLDER = "metadata"

_METADATA_STATEMENT_REQUIRED_DEFAULTS: Mapping[str, Any] = {
    "description": "",
    "authenticatorVersion": 0,
    "schema": 3,
    "upv": [],
    "attestationTypes": [],
    "userVerificationDetails": [],
    "keyProtection": [],
    "matcherProtection": [],
    "attachmentHint": [],
    "tcDisplay": [],
    "attestationRootCertificates": [],
}
