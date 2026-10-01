"""``decoder.encode.handlers_basic``: the encoder's formats, named in the Codec's words."""
from __future__ import annotations

import pytest

from server.app.decoder.encode import text as encode_text


@pytest.mark.parametrize(("fmt", "error"), [("   ", "Encoder format must be provided"), ("XML", "Unsupported encoder format: XML")])
def test_a_format_must_be_one_the_codec_names(fmt, error):
    with pytest.raises(ValueError, match=error):
        encode_text.encode_payload_text('{"ok": true}', fmt)
