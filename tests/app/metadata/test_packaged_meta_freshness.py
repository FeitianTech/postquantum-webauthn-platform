"""The packaged explorer snapshot is trusted by content, not by file mtime."""

from __future__ import annotations

import json
import os

import pytest


@pytest.fixture
def metadata_module(monkeypatch, tmp_path, metadata_runtime_state):
    module = pytest.importorskip("server.app.metadata")

    verified_path = tmp_path / "fido-mds3.verified.json"
    explorer_path = tmp_path / "fido-mds3.explorer.json"
    verified_path.write_text(json.dumps({"entries": []}), encoding="utf-8")
    explorer_path.write_text(
        json.dumps({"entries": [], "meta": {"no": 7, "source": "packaged-snapshot"}}),
        encoding="utf-8",
    )

    # Simulate a checkout where the explorer file ends up slightly older.
    os.utime(explorer_path, (1_000.0, 1_000.0))
    os.utime(verified_path, (1_000.5, 1_000.5))

    monkeypatch.setattr(module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)
    monkeypatch.setattr(module, "MDS_EXPLORER_PATH", str(explorer_path), raising=False)

    builds = []
    monkeypatch.setattr(
        module,
        "build_explorer_snapshot",
        lambda payload, cache: builds.append(1) or {"entries": [], "meta": {"source": "rebuilt"}},
        raising=False,
    )
    monkeypatch.setattr(module, "load_metadata_cache_entry", lambda: None, raising=False)

    module._test_paths = (verified_path, explorer_path)
    module._test_builds = builds
    return module


def _write_meta(verified_path, explorer_path, *, verified_no=7, explorer_no=7):
    (verified_path.parent / (verified_path.name + ".meta.json")).write_text(
        json.dumps({"no": verified_no, "etag": "7", "generated_at": "2026-09-10T00:00:00+00:00"}),
        encoding="utf-8",
    )
    (explorer_path.parent / (explorer_path.name + ".meta.json")).write_text(
        json.dumps(
            {
                "no": explorer_no,
                "etag": "7",
                "generatedAt": "2026-09-10T00:00:00+00:00",
                "source": "packaged",
            }
        ),
        encoding="utf-8",
    )


def test_matching_meta_uses_packaged_snapshot_despite_older_mtime(metadata_module):
    verified_path, explorer_path = metadata_module._test_paths
    _write_meta(verified_path, explorer_path)

    snapshot, _ = metadata_module._load_base_explorer_snapshot()

    assert snapshot["meta"]["source"] == "packaged-snapshot"
    assert metadata_module._test_builds == []


def test_mismatched_meta_rebuilds_from_verified_snapshot(metadata_module):
    verified_path, explorer_path = metadata_module._test_paths
    _write_meta(verified_path, explorer_path, explorer_no=6)

    snapshot, _ = metadata_module._load_base_explorer_snapshot()

    assert snapshot["meta"]["source"] == "rebuilt"
    assert metadata_module._test_builds == [1]


def test_summary_reads_meta_file_without_loading_snapshot(metadata_module, monkeypatch):
    verified_path, explorer_path = metadata_module._test_paths
    _write_meta(verified_path, explorer_path)
    monkeypatch.setattr(
        metadata_module,
        "_load_base_explorer_snapshot",
        lambda: pytest.fail("summary should not load the full explorer snapshot"),
        raising=False,
    )

    summary = metadata_module.load_packaged_explorer_summary()

    assert summary["no"] == 7
    assert summary["source"] == "packaged"
