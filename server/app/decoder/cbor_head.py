"""The one writer of a CBOR item's head: its major type and argument (RFC 8949 section 3).

The head is as short as the argument allows unless ``info`` names the
additional information to write: 0..23 carries the argument itself, 24..27 an
argument of 1, 2, 4 or 8 bytes after the initial byte, 31 an indefinite length
(no argument). The canonical encoder always writes the shortest; the EDN
encoder writes whatever width a notation's encoding indicator asks for.
"""
from __future__ import annotations

# Additional information 24..27: how many bytes of argument follow.
ARGUMENT_BYTES = {24: 1, 25: 2, 26: 4, 27: 8}
INDEFINITE = 31


def shortest_info(argument: int) -> int:
    """The additional information of the shortest head that holds ``argument``."""

    if argument < 24:
        return argument
    for info, width in ARGUMENT_BYTES.items():
        if argument < 1 << (8 * width):
            return info
    raise ValueError(f"{argument} does not fit in a CBOR head's 64-bit argument")


def encode_head(major_type: int, argument: int | None, info: int | None = None) -> bytes:
    """The head of a major-type ``major_type`` item, shortest unless ``info`` is given."""

    if not 0 <= major_type <= 7:
        raise ValueError(f"CBOR major types are 0..7, not {major_type}")
    if info == INDEFINITE:
        if argument is not None:
            raise ValueError("an indefinite-length head carries no argument")
        return bytes([(major_type << 5) | INDEFINITE])
    if not isinstance(argument, int) or argument < 0:
        raise ValueError("a CBOR head's argument is a non-negative integer")
    if info is None:
        info = shortest_info(argument)
    if info < 24:
        if argument != info:
            raise ValueError(f"additional information {info} is the argument itself, not {argument}")
        return bytes([(major_type << 5) | info])
    width = ARGUMENT_BYTES.get(info)
    if width is None:
        raise ValueError(f"additional information {info} is reserved")
    if argument >= 1 << (8 * width):
        raise ValueError(f"{argument} does not fit in a {width}-byte argument")
    return bytes([(major_type << 5) | info]) + argument.to_bytes(width, "big")
