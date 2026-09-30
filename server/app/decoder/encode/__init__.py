"""The encoder: a value in JSON, EDN or a binary spelling, written as CBOR, COSE, CTAP, DER or PEM.

``text`` is the entry (``encode_payload_text``); the handlers, the CTAP field
encoders and the binary readers it uses are the other modules. Importers name
the module they need; this package re-exports nothing.
"""
