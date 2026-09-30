#!/usr/bin/env python3
"""Precompress the UI's export for serving.

Writes a ``.gz`` copy of each compressible file under DIR (``web/out``) when the
copy is smaller, so the server sends it to gzip clients instead of compressing per
request (``server/app/routes/web_export.py``, ``send_precompressed``). The export's
file names carry their own content hashes. Run at image build time; the copies
are not committed.

usage: build_static_assets.py DIR
"""

from __future__ import annotations

import gzip
import sys
from collections.abc import Iterator
from pathlib import Path

COMPRESSIBLE_SUFFIXES = frozenset({".css", ".html", ".js", ".json", ".map", ".svg", ".txt"})
MIN_COMPRESS_BYTES = 1024


def iter_static_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix != ".gz":
            yield path


def precompress(root: Path) -> int:
    written = 0
    for path in iter_static_files(root):
        if path.suffix not in COMPRESSIBLE_SUFFIXES:
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
    if len(argv) != 2:
        print("usage: build_static_assets.py DIR", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    written = precompress(root)
    print(f"Precompressed {written} files under {root}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
