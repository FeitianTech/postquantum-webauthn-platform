"""The decoder: what an input to the Codec is, read without repairing it (docs/DECODER.md).

``text`` is the entry (``decode_payload_text``); ``cbor_parser`` is the one
CBOR parser, ``answer`` builds what the Codec answers, and the other modules each read one
kind of input or report one kind of finding. Importers name the module they
need; this package re-exports nothing.
"""
