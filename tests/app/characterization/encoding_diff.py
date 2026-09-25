"""Show that the characterization goldens differ from a revision only in byte spellings.

Usage (from the repository root)::

    python tests/app/characterization/encoding_diff.py [REVISION]

For every golden file changed since REVISION (default ``HEAD``) it walks the old
and the new record side by side. A string that changed must be standard base64
in the old record and base64url in the new, the two decoding to the same bytes.
A ``bodySha256`` / ``sha256`` and a ``Content-Length`` header may change with
them. Anything else is listed, and the exit status is 1.
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = "tests/app/characterization/golden"
HASH_KEYS = {"bodySha256", "sha256"}


def _changed_files(revision: str) -> list[str]:
    output = subprocess.run(
        ["git", "diff", "--name-only", revision, "--", GOLDEN],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in output.splitlines() if line.endswith(".json")]


def _old_record(revision: str, path: str):
    text = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(text)


def _same_bytes(encoding, old: str, new: str) -> bool:
    before = encoding.try_decode_base64(old, ignore_whitespace=False)
    after = encoding.try_decode_base64url(new, ignore_whitespace=False)
    return before is not None and before == after and "=" not in new


def _walk(encoding, old, new, where: str, tally: Counter, others: list[str]) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new), key=str):
            if key not in old or key not in new:
                others.append(f"{where}/{key}: only in the {'new' if key in new else 'old'} record")
                continue
            _walk(encoding, old[key], new[key], f"{where}/{key}", tally, others)
        return
    if isinstance(old, list) and isinstance(new, list):
        if (
            len(old) == len(new) == 2
            and old[0] == new[0]
            and isinstance(old[0], str)
            and old[0].lower() == "content-length"
        ):
            tally["Content-Length"] += old[1] != new[1]
            return
        if len(old) != len(new):
            others.append(f"{where}: {len(old)} items became {len(new)}")
            return
        for index, (before, after) in enumerate(zip(old, new)):
            _walk(encoding, before, after, f"{where}[{index}]", tally, others)
        return
    if old == new:
        return
    key = where.rsplit("/", 1)[-1]
    if key in HASH_KEYS:
        tally["hashes"] += 1
    elif isinstance(old, str) and isinstance(new, str) and _same_bytes(encoding, old, new):
        tally["re-spelled"] += 1
        tally[f"field {key}"] += 1
    else:
        others.append(f"{where}: {json.dumps(old)[:80]} -> {json.dumps(new)[:80]}")


def main(argv: list[str]) -> int:
    revision = argv[1] if len(argv) > 1 else "HEAD"
    sys.path.insert(0, str(ROOT))
    encoding = importlib.import_module("server.app.encoding")

    files = _changed_files(revision)
    tally: Counter = Counter()
    others: list[str] = []
    for path in files:
        new = json.loads((ROOT / path).read_text(encoding="utf-8"))
        _walk(encoding, _old_record(revision, path), new, path, tally, others)

    print(f"{len(files)} golden files changed since {revision}")
    print(f"  {tally['re-spelled']} values re-spelled from base64 to base64url, the same bytes each")
    for label, count in sorted(tally.items()):
        if label.startswith("field "):
            print(f"    {label[6:]}: {count}")
    print(f"  {tally['hashes']} body hashes and {tally['Content-Length']} Content-Length headers changed with them")
    print(f"  {len(others)} other differences")
    for line in others:
        print(f"    {line}")
    return 1 if others else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
