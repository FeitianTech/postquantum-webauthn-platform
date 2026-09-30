"""Configuration and setup for the Flask application.

Importers name the submodule they need, and patch there; this package
re-exports nothing.

Importing the package configures nothing and writes nothing.
``server.app.factory.create_app()`` builds an app from these submodules: the
``config_from_env()`` ones supply settings, the ``init_app()`` ones configure the
app, in the order ``factory.INIT_STEPS`` fixes.

- ``paths``: the project and instance locations, each store's directory
  (``store_dir``), and ``basepath``.
- ``application``: ``build_app()``, the bare Flask object.
- ``logs``: attaches the handler every module logger reaches stderr through.
- ``session_secret``: the session secret. May write
  ``<instance_path>/session-secret.key`` when an app is built.
- ``proxy``: ``ProxyFix`` when the forwarded headers are trusted (never
  ``X-Forwarded-Host``).
- ``compression``: the gzip ``after_request`` handler.
- ``security_headers``: CSP, Permissions-Policy, HSTS and friends. Its
  ``after_request`` handler is registered after ``compression``'s, and Flask runs
  them in reverse, so the headers are set before the body is compressed.
- ``session_cookie``: the session cookie's flags and lifetime.
- ``request_limits``: how large a request body the app reads.
- ``origins``: the exact-origin allowlist and the origin helpers.
- ``attestation_trust``: operator-trusted attestation CAs.
- ``mds``: where the session metadata lives (the
  snapshot's own files: ``server.app.mds.files``).
- ``web_export``: where the UI's static export is (``web/out``), served at ``/``.
- ``relying_party``: the RP ID and name, and ``create_fido_server``.

The MDS trust anchors live in ``server.app.mds.trust``, outside this package, so
the snapshot updater can import them without anything from Flask.
"""
