"""JSON that decoder input holds: the input text itself, or bytes that are UTF-8 JSON."""
from __future__ import annotations

import json
from typing import Any


def _try_parse_json(value: str) -> Any | None:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None
