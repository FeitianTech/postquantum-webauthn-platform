"""The one reader of boolean environment settings."""

from __future__ import annotations

import logging
import os

__all__ = ["parse_env_flag"]

logger = logging.getLogger(__name__)

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})
# (name, value) pairs already warned about: some settings are read on every request.
_warned: set[tuple[str, str]] = set()


def parse_env_flag(name: str) -> bool | None:
    """``True`` or ``False`` when ``name`` is set to a known spelling, else ``None``.

    ``1``/``true``/``yes``/``on`` read True and ``0``/``false``/``no``/``off`` or
    nothing read False, in any case and with surrounding space. Any other value is
    no setting: the caller's default applies, and it is warned about once.
    """

    raw = os.environ.get(name)
    if raw is None:
        return None
    normalised = raw.strip().lower()
    if normalised in _TRUE:
        return True
    if normalised in _FALSE:
        return False
    if (name, raw) not in _warned:
        _warned.add((name, raw))
        logger.warning("Ignoring %s=%r: expected one of 1/true/yes/on or 0/false/no/off.", name, raw)
    return None
