"""The settings the metadata modules share.

A leaf: it imports nothing from ``server.app``, so any module here can depend on
it. The snapshot's caches are ``server.app.mds.cache.CACHE``; the visitor
session's settings and cleanup are ``server.app.visitor_session``'s.
"""
from __future__ import annotations

_METADATA_REPO_FOLDER = "metadata"
