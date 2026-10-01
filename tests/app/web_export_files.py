"""A small stand-in for the UI's static export (``web/out``), for the tests of
what the app serves from it. The ``export_root`` fixture (``tests/app/conftest.py``)
writes it into ``tmp_path``: pytest never needs Node, and never reads a ``web/out``
a local build may be writing.
"""
from __future__ import annotations

import gzip
from pathlib import Path

INDEX = b"<!DOCTYPE html><html><head><title>Index</title></head><body>index page " + b"x" * 600 + b"</body></html>"
NOT_FOUND = b"<!DOCTYPE html><html><body>export 404 page</body></html>"
CHUNK = b"console.log('chunk');\n" * 200


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_export(root: Path) -> Path:
    write(root / "index.html", INDEX)
    write(root / "404.html", NOT_FOUND)
    write(root / "500.html", b"<!DOCTYPE html><html><body>500</body></html>")
    write(root / "_next" / "static" / "chunks" / "main-abc123.js", CHUNK)
    write(root / "_next" / "static" / "chunks" / "main-abc123.js.gz", gzip.compress(CHUNK))
    write(root / "_next" / "static" / "media" / "geist.woff2", b"wOF2font")
    return root
