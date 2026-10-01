from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.app.mds import effective as mds_effective


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    """A fresh MDS cache and sweep state."""


def test_base_explorer_snapshot_and_summary_and_resolution_session_match(metadata_module, monkeypatch, sessions, effective):
    item = SimpleNamespace(payload={"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}, uploaded_at="now")
    monkeypatch.setattr(sessions, "list_session_metadata_items", lambda: [item])
    monkeypatch.setattr(effective, "_entry_matches_lookup", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(effective, "_session_item_source_info", lambda _item: {"source": "session"})
    monkeypatch.setattr(
        effective,
        "build_explorer_entry",
        lambda payload, **_kwargs: {"source": "session", "payload": payload},
    )
    resolved = mds_effective.resolve_effective_metadata_entry(entry_id="any")
    assert resolved["source"] == "session"
