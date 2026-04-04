#!/usr/bin/env python3
"""Write shields.io endpoint JSON files under .github/badges/ for README coverage badges."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BADGES_DIR = ROOT / ".github" / "badges"
# Written by `npm run test:python:coverage:json` (gitignored)
DEFAULT_PYTHON_COVERAGE_JSON = ROOT / "coverage" / "python-coverage.json"


def color(pct: float) -> str:
    if pct >= 80:
        return "brightgreen"
    if pct >= 60:
        return "yellow"
    return "red"


def fmt_pct(pct: float) -> str:
    s = f"{pct:.2f}".rstrip("0").rstrip(".")
    return f"{s}%"


def load_python_percent() -> float:
    env = os.environ.get("PYTHON_COVERAGE_JSON", "").strip()
    path = Path(env).expanduser() if env else DEFAULT_PYTHON_COVERAGE_JSON
    if not path.is_file():
        raise FileNotFoundError(
            "Missing Python coverage JSON. Run: npm run test:python:coverage:json "
            f"(needs pip install coverage pytest), or set PYTHON_COVERAGE_JSON. "
            f"Expected: {path}"
        )
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return float(data["totals"]["percent_covered"])


def load_frontend_percent() -> float:
    path = ROOT / "coverage" / "frontend" / "coverage-summary.json"
    if not path.is_file():
        raise FileNotFoundError(f"Run frontend coverage first (missing {path})")
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return float(data["total"]["lines"]["pct"])


# shields.io endpoint cache; keep modest so README badges refresh soon after JSON updates on main.
BADGE_CACHE_SECONDS = 120


def write_badge(name: str, label: str, pct: float, named_logo: str) -> None:
    payload = {
        "schemaVersion": 1,
        "label": label,
        "message": fmt_pct(pct),
        "color": color(pct),
        "namedLogo": named_logo,
        "cacheSeconds": BADGE_CACHE_SECONDS,
    }
    out = BADGES_DIR / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    py = load_python_percent()
    fe = load_frontend_percent()
    write_badge("python-coverage.json", "Python coverage", py, "python")
    write_badge("frontend-coverage.json", "Frontend coverage", fe, "javascript")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
