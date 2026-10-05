"""Attestation: the checks a registration's attestation goes through, and its certificates.

``checks`` runs every check (``perform_attestation_checks``) in order, over
``request_expectations`` (what the request expected), ``response_checks`` (the
response against it), ``statement_checks`` (the attestation statement's signature,
trust path and root) and ``metadata_checks`` (the MDS entry); ``classical`` and
``evaluation`` validate the trust path against the MDS metadata, ``chain``
verifies certificate chains, ``trust`` holds the trust anchors and roots, and
``certificates`` (with ``certificate_names``, ``certificate_extensions``,
``certificate_public_keys`` and ``certificate_summary``) serialises a
certificate for the page. ``aaguid`` reads the AAGUID and the extension outputs,
``formatting`` spells hex, and ``constants`` holds the OIDs. Importers name the
module they need; this package re-exports nothing.
"""
