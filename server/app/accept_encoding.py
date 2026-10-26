"""The one reader of a request's Accept-Encoding: whether an answer may be gzipped.

RFC 9110 §12.5.3: a coding with weight 0 is refused, ``*`` stands for every coding
the header does not name, and ``identity`` (no coding) can be preferred or refused
like any other. Read without a regular expression, so a hostile header costs time in
proportion to its length.
"""

from __future__ import annotations

__all__ = ["gzip_accepted"]

_DIGITS = frozenset("0123456789")


def _weight(text: str) -> float | None:
    """A qvalue: ``0`` to ``1`` with at most three decimals; None for anything else."""

    whole, dot, fraction = text.partition(".")
    if len(fraction) > 3 or not set(fraction) <= _DIGITS:
        return None
    if whole == "0":
        return float(f"0.{fraction}") if fraction else 0.0
    if whole == "1" and not fraction.strip("0"):
        return 1.0
    return None


def _element_weight(parameters: list[str]) -> float | None:
    """An element's weight from its parameters: its ``q``, else 1; None when the ``q`` does not read."""

    for parameter in parameters:
        name, _equals, value = parameter.partition("=")
        if name.strip().lower() == "q":
            return _weight(value.strip())
    return 1.0


def _weights(header: str) -> dict[str, float]:
    """Each coding the header names, with its highest weight; an element whose weight does not read is left out."""

    weights: dict[str, float] = {}
    for element in header.split(","):
        coding, *parameters = element.split(";")
        coding = coding.strip().lower()
        weight = _element_weight(parameters)
        if coding and weight is not None:
            weights[coding] = max(weight, weights.get(coding, 0.0))
    return weights


def gzip_accepted(header: str | None) -> bool:
    """Whether a request whose Accept-Encoding is ``header`` takes a gzipped answer.

    Gzip must have a weight above zero (its own, ``x-gzip``'s or ``*``'s), and no less
    than the one the header gives identity (its own or ``*``'s; none when it names
    neither, so ``gzip;q=0.5`` alone still takes gzip). No header takes none.
    """

    weights = _weights(header or "")
    wildcard = weights.get("*")
    gzip = weights.get("gzip", weights.get("x-gzip", wildcard if wildcard is not None else 0.0))
    identity = weights.get("identity", wildcard if wildcard is not None else 0.0)
    return gzip > 0 and gzip >= identity
