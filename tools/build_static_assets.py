#!/usr/bin/env python3
"""Prepare frontend static assets for long-lived caching.

Writes ``frontend/BUILD_ID`` (a content hash used in versioned asset URLs) and a
precompressed ``.gz`` copy of each compressible file, so the server neither
gzips assets per request nor serves a stale file under a new URL.
Run at image build time; outputs are not committed.
"""

from __future__ import annotations

import gzip
import hashlib
import sys
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATIC_ROOT = REPO_ROOT / "frontend" / "static"

COMPRESSIBLE_SUFFIXES = frozenset({".css", ".html", ".js", ".json", ".map", ".svg", ".txt"})
MIN_COMPRESS_BYTES = 1024
# Read by the server from disk only; never requested by browsers.
SKIPPED_FILES = frozenset({"blob.jwt", "fido-mds3.verified.json", "fido-mds3.explorer.json"})


def iter_static_files(static_root: Path) -> Iterator[Path]:
    for path in sorted(static_root.rglob("*")):
        if path.is_file() and path.suffix != ".gz":
            yield path


def compute_build_id(static_root: Path) -> str:
    digest = hashlib.sha256()
    for path in iter_static_files(static_root):
        digest.update(path.relative_to(static_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()[:12]


def precompress(static_root: Path) -> int:
    written = 0
    for path in iter_static_files(static_root):
        if path.suffix not in COMPRESSIBLE_SUFFIXES or path.name in SKIPPED_FILES:
            continue
        data = path.read_bytes()
        if len(data) < MIN_COMPRESS_BYTES:
            continue
        compressed = gzip.compress(data, compresslevel=9, mtime=0)
        if len(compressed) >= len(data):
            continue
        Path(f"{path}.gz").write_bytes(compressed)
        written += 1
    return written


def main(argv: list[str]) -> int:
    static_root = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_STATIC_ROOT
    build_id = compute_build_id(static_root)
    written = precompress(static_root)
    (static_root.parent / "BUILD_ID").write_text(f"{build_id}\n", encoding="utf-8")
    print(f"Static assets ready: build id {build_id}, {written} gzip files written.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
