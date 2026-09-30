"""The WebAuthn and FIDO layer.

``attestation`` verifies attestation statements and their trust paths, ``pqc``
adapts the ML-DSA algorithms, and ``sign_count`` implements the signature-counter
check; the FIDO MDS is ``server.app.mds``. Importers name the
submodule they need; this package re-exports nothing. It does import
``cose_keys``, whose classes fido2 finds only once they are defined, so any use
of this package registers the COSE algorithms the app adds to fido2's.
"""
from . import cose_keys

__all__ = ["cose_keys"]
