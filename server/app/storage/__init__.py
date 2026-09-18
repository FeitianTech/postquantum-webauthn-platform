"""Persistence for the demo server.

``credentials`` holds registered credentials, ``session_metadata`` holds the
per-session metadata uploads, ``cloud`` is the Google Cloud Storage backend both
can sit on, and ``common`` holds the containment checks they share. Importers
name the submodule they need; this package deliberately re-exports nothing.
"""
