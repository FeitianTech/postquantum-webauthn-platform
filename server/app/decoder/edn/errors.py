"""EDN that is not valid: why, and where in the text as sent it stops being valid.

The reader and the string literals' reader raise it alike, so every refusal of
EDN carries the offset ``/api/codec`` answers with.
"""
from __future__ import annotations


class EdnError(ValueError):
    """EDN that is not valid, with the offset in the text as sent where it stops being valid."""

    def __init__(self, reason: str, offset: int) -> None:
        self.offset = offset
        super().__init__(f"EDN is not valid at offset {offset}: {reason}")
