"""The Simple tab's field lookup in a client-supplied credential record.

Bytes are read by :mod:`server.app.webauthn.client_binary`, which both tabs share.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _select_first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    """Return the value of the first key in *keys* present in *mapping*.

    Unlike ``advanced.parsing._select_first``, a present-but-``None`` value is
    returned rather than skipped.
    """

    for key in keys:
        if key in mapping:
            return mapping[key]
    return None
