"""The FIDO Metadata Service (MDS) snapshot: where it comes from, how it is kept, what is read from it.

The snapshot updater (``tools/update_mds_snapshot.py``) imports ``trust``,
``blob``, ``revocation``, ``entries``, ``files``, ``snapshot`` and ``sets``
without Flask, so this package imports nothing and re-exports nothing:
importers name the module they need.
"""
