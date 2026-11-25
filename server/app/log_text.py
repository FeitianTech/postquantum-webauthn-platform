"""Text a client chose, as a log line carries it.

Production's log is plain text, one record a line: a file name, a path or a username a
request sent is written so that it stays on its line and where it ends shows. One plain
word of at most ``LIMIT`` characters (``authenticator.json``, ``metadata/a.json``,
``example.com``) reads as sent; anything else is quoted with Python's escapes, so a line
break, a carriage return or an escape character is written as ``\\n``, ``\\r`` or
``\\x1b``, and only its first ``LIMIT`` characters are, with how many it had.
"""

from __future__ import annotations

import re

__all__ = ["LIMIT", "client_text"]

LIMIT = 200
# ASCII letters, digits and the punctuation of a file name, a path or a host: a word that ends
# where the server's words start again.
_PLAIN_WORD = re.compile(r"[\w.@:/+~-]+", re.ASCII)


def client_text(value: object) -> str:
    """``value`` as a log line carries it: as sent when it is one plain word, else quoted."""

    text = str(value)
    if len(text) > LIMIT:
        return f"{text[:LIMIT]!r}... ({len(text):,} characters)"
    return text if _PLAIN_WORD.fullmatch(text) else repr(text)
