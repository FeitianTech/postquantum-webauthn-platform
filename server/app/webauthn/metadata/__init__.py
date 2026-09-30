"""The FIDO MDS runtime: the packaged snapshot, visitors' uploaded metadata, the verifier.

``entries`` reads uploaded metadata statements, ``sessions`` keeps each visitor's uploads,
``effective`` merges the snapshot with a visitor's uploads, ``verifier`` builds
fido2's MDS verifier from them, and ``uploads`` mirrors uploads to GitHub.
Importers name the module they need; this package re-exports nothing.
"""
