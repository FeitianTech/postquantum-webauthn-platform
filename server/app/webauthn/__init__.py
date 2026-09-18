"""The WebAuthn and FIDO layer.

``attestation`` verifies attestation statements and their trust paths,
``metadata`` resolves FIDO MDS entries, ``pqc`` adapts the ML-DSA algorithms, and
``sign_count`` implements the signature-counter check. Importers name the
submodule they need; this package deliberately re-exports nothing.
"""
