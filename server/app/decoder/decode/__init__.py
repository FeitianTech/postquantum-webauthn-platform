"""The decoder: what an input to the Codec is, read without repairing it (docs/DECODER.md).

``text`` is the entry (``decode_payload_text``); ``cbor_parser`` is the one
CBOR parser, ``answer`` builds what the Codec answers (its authenticator data view in
``answer_auth_data``, the bytes it reads back in ``answer_bytes``), and the other modules each read one
kind of input or report one kind of finding. Importers name the module they
need; this package re-exports nothing.
"""
