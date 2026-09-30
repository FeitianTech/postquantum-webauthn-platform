"""The server's stores (docs/STORAGE.md).

``credentials`` holds the Simple tab's registered credentials (in
``record_format``), ``credential_artifacts`` the Advanced tab's registrations,
``session_metadata`` the per-session metadata uploads, and ``github_mirror``
copies registrations and uploads to the credential log repository. ``cloud`` is
the Google Cloud Storage backend the stores can sit on, and ``common`` holds
the containment checks and the session prefix they share. Importers name the
submodule they need; this package deliberately re-exports nothing.
"""
