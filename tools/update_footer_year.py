#!/usr/bin/env python3
"""Update the footer copyright year in the main HTML template."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HTML_PATH = REPO_ROOT / "frontend" / "templates" / "index.html"

FOOTER_YEAR_PATTERN = re.compile(
    r"(?P<prefix>©|&copy;)\s+\d{4}\s+Feitian Technologies Co\., Ltd\."
)


def update_footer_year(path: Path, *, year: int | None = None) -> bool:
    target_year = year if year is not None else datetime.now(timezone.utc).year
    text = path.read_text(encoding="utf-8")

    def _replace(match: re.Match[str]) -> str:
        return f"{match.group('prefix')} {target_year} Feitian Technologies Co., Ltd."

    updated_text, replacements = FOOTER_YEAR_PATTERN.subn(_replace, text, count=1)
    if replacements == 0:
        raise ValueError(f"No footer year found to update in {path}")

    if updated_text == text:
        return False

    path.write_text(updated_text, encoding="utf-8")
    return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_HTML_PATH,
        help="Path to the HTML file containing the copyright footer.",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Explicit year override (defaults to current UTC year).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        changed = update_footer_year(args.path, year=args.year)
    except (OSError, ValueError) as exc:
        print(f"::error::{exc}")
        return 1

    if changed:
        print(f"Updated footer year to {args.year or datetime.now(timezone.utc).year}")
    else:
        print("Footer year already up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
