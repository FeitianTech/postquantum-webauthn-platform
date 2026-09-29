"""Store credential records the way the routes do: read, then compare-and-swap."""

from __future__ import annotations

from typing import Any


def seed_records(store: Any, name: str, records: Any, *, session_id: str) -> None:
    _, version = store.read_for_update(name, session_id=session_id)
    assert store.save_if_unchanged(name, records, version, session_id=session_id)
