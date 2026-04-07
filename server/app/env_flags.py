"""Shared helpers for parsing boolean-like environment flags."""

from __future__ import annotations

import os
from typing import Optional

__all__ = ["parse_env_flag"]


def parse_env_flag(name: str) -> Optional[bool]:
    """Return ``True``/``False`` when ``name`` is explicitly set, otherwise ``None``."""

    raw = os.environ.get(name)
    if raw is None:
        return None

    normalised = raw.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True
