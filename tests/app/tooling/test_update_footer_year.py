from __future__ import annotations

from pathlib import Path

import pytest

import tools.update_footer_year as updater


def test_update_footer_year_updates_first_footer_match_only(tmp_path: Path):
    html = (
        "<footer>\n"
        "  <p>&copy; 2024 Feitian Technologies Co., Ltd. All rights reserved.</p>\n"
        "  <p>&copy; 1999 Feitian Technologies Co., Ltd.</p>\n"
        "</footer>\n"
    )
    html_path = tmp_path / "index.html"
    html_path.write_text(html, encoding="utf-8")

    changed = updater.update_footer_year(html_path, year=2026)

    assert changed is True
    updated = html_path.read_text(encoding="utf-8")
    assert "&copy; 2026 Feitian Technologies Co., Ltd. All rights reserved." in updated
    assert "&copy; 1999 Feitian Technologies Co., Ltd." in updated


def test_update_footer_year_returns_false_when_already_current(tmp_path: Path):
    html_path = tmp_path / "index.html"
    html_path.write_text(
        "<p>&copy; 2026 Feitian Technologies Co., Ltd. All rights reserved.</p>\n",
        encoding="utf-8",
    )

    changed = updater.update_footer_year(html_path, year=2026)

    assert changed is False


def test_update_footer_year_raises_when_footer_pattern_missing(tmp_path: Path):
    html_path = tmp_path / "index.html"
    html_path.write_text("<p>No copyright footer here.</p>\n", encoding="utf-8")

    with pytest.raises(ValueError, match="No footer year found"):
        updater.update_footer_year(html_path, year=2026)


def test_main_reports_update_and_noop(tmp_path: Path, capsys):
    html_path = tmp_path / "index.html"
    html_path.write_text(
        "<p>&copy; 2020 Feitian Technologies Co., Ltd. All rights reserved.</p>\n",
        encoding="utf-8",
    )

    first_exit = updater.main(["--path", str(html_path), "--year", "2026"])
    first_output = capsys.readouterr().out
    assert first_exit == 0
    assert "Updated footer year to 2026" in first_output

    second_exit = updater.main(["--path", str(html_path), "--year", "2026"])
    second_output = capsys.readouterr().out
    assert second_exit == 0
    assert "Footer year already up to date." in second_output


def test_main_reports_error_for_missing_footer(tmp_path: Path, capsys):
    html_path = tmp_path / "index.html"
    html_path.write_text("<p>Missing target footer text.</p>\n", encoding="utf-8")

    exit_code = updater.main(["--path", str(html_path), "--year", "2026"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "::error::No footer year found to update" in output


def test_main_updates_every_footer_it_is_given(tmp_path: Path, capsys):
    html_path = tmp_path / "index.html"
    html_path.write_text("<p>&copy; 2025 Feitian Technologies Co., Ltd. All rights reserved.</p>\n", encoding="utf-8")
    tsx_path = tmp_path / "Footer.tsx"
    tsx_path.write_text("<p>\u00a9 2025 Feitian Technologies Co., Ltd. All rights reserved.</p>\n", encoding="utf-8")

    exit_code = updater.main(["--path", str(html_path), "--path", str(tsx_path), "--year", "2027"])

    assert exit_code == 0
    assert "&copy; 2027 Feitian" in html_path.read_text(encoding="utf-8")
    assert "\u00a9 2027 Feitian" in tsx_path.read_text(encoding="utf-8")
    assert "Updated footer year to 2027" in capsys.readouterr().out


def test_the_defaults_are_both_uis_footers_and_each_holds_the_year():
    assert updater.DEFAULT_PATHS == (
        updater.REPO_ROOT / "frontend" / "templates" / "index.html",
        updater.REPO_ROOT / "web" / "src" / "components" / "shell" / "Footer.tsx",
    )
    for path in updater.DEFAULT_PATHS:
        assert updater.FOOTER_YEAR_PATTERN.search(path.read_text(encoding="utf-8")), path


def test_main_without_paths_updates_the_defaults(monkeypatch, tmp_path: Path, capsys):
    first = tmp_path / "a.html"
    second = tmp_path / "b.tsx"
    for path in (first, second):
        path.write_text("\u00a9 2026 Feitian Technologies Co., Ltd.\n", encoding="utf-8")
    monkeypatch.setattr(updater, "DEFAULT_PATHS", (first, second))

    assert updater.main(["--year", "2026"]) == 0
    assert "Footer year already up to date." in capsys.readouterr().out
