"""The decoder: what an input to the Codec is, read without repairing it (docs/DECODER.md).

``pipeline`` is the entry (``decode_payload_text``); ``cbor_parser`` is the one
CBOR parser, ``response`` shapes the answer, and the other modules each read one
kind of input or report one kind of finding. Importers name the module they
need; this package re-exports nothing.
"""
