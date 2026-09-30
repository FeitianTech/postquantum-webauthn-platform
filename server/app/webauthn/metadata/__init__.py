"""What the app makes of uploaded metadata and of the snapshot's entries.

``entries`` reads uploaded metadata statements, ``effective`` merges the snapshot
with a visitor's uploads, ``verifier`` builds fido2's MDS verifier from them, and
``uploads`` mirrors uploads to GitHub. Importers name the module they need; this
package re-exports nothing.
"""
