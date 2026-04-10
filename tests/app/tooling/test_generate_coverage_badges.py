from __future__ import annotations

import json

import pytest

import tools.generate_coverage_badges as badges


def _write_json(path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_color_thresholds_and_percent_formatting():
    assert badges.color(80.0) == "brightgreen"
    assert badges.color(79.99) == "yellow"
    assert badges.color(60.0) == "yellow"
    assert badges.color(59.99) == "red"

    assert badges.fmt_pct(97.0) == "97%"
    assert badges.fmt_pct(97.5) == "97.5%"
    assert badges.fmt_pct(97.56) == "97.56%"


def test_load_python_percent_prefers_env_override_and_falls_back_to_default(tmp_path, monkeypatch):
    env_path = tmp_path / "python-env.json"
    default_path = tmp_path / "python-default.json"
    _write_json(env_path, {"totals": {"percent_covered": 91.25}})
    _write_json(default_path, {"totals": {"percent_covered": 88.0}})

    monkeypatch.setenv("PYTHON_COVERAGE_JSON", str(env_path))
    monkeypatch.setattr(badges, "DEFAULT_PYTHON_COVERAGE_JSON", default_path, raising=False)

    assert badges.load_python_percent() == 91.25

    monkeypatch.setenv("PYTHON_COVERAGE_JSON", "   ")
    assert badges.load_python_percent() == 88.0


def test_load_python_percent_raises_clear_error_for_missing_file(tmp_path, monkeypatch):
    missing_path = tmp_path / "missing-python.json"
    monkeypatch.setenv("PYTHON_COVERAGE_JSON", str(missing_path))

    with pytest.raises(FileNotFoundError, match="Missing Python coverage JSON"):
        badges.load_python_percent()


def test_load_frontend_percent_reads_summary_and_raises_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(badges, "ROOT", tmp_path, raising=False)

    summary_path = tmp_path / "coverage" / "frontend" / "coverage-summary.json"
    _write_json(
        summary_path,
        {"total": {"lines": {"pct": 98.7, "covered": 987, "total": 1000}}},
    )
    assert badges.load_frontend_percent() == 98.7

    summary_path.unlink()
    with pytest.raises(FileNotFoundError, match="Run frontend coverage first"):
        badges.load_frontend_percent()


def test_write_badge_creates_parent_and_writes_expected_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(badges, "BADGES_DIR", tmp_path / "badges", raising=False)

    badges.write_badge("python-coverage.json", "Python (combined)", 95.5, "python")

    payload = json.loads((tmp_path / "badges" / "python-coverage.json").read_text(encoding="utf-8"))
    assert payload == {
        "schemaVersion": 1,
        "label": "Python (combined)",
        "message": "95.5%",
        "color": "brightgreen",
        "namedLogo": "python",
        "cacheSeconds": badges.BADGE_CACHE_SECONDS,
    }


def test_main_generates_frontend_and_python_badges_from_coverage_inputs(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTHON_COVERAGE_JSON", raising=False)

    monkeypatch.setattr(badges, "ROOT", tmp_path, raising=False)
    monkeypatch.setattr(badges, "BADGES_DIR", tmp_path / ".github" / "badges", raising=False)
    monkeypatch.setattr(
        badges,
        "DEFAULT_PYTHON_COVERAGE_JSON",
        tmp_path / "coverage" / "python-coverage.json",
        raising=False,
    )

    _write_json(
        badges.DEFAULT_PYTHON_COVERAGE_JSON,
        {"totals": {"percent_covered": 96.2}},
    )
    _write_json(
        tmp_path / "coverage" / "frontend" / "coverage-summary.json",
        {"total": {"lines": {"pct": 97.4, "covered": 974, "total": 1000}}},
    )

    assert badges.main() == 0

    python_badge = json.loads(
        (tmp_path / ".github" / "badges" / "python-coverage.json").read_text(encoding="utf-8")
    )
    frontend_badge = json.loads(
        (tmp_path / ".github" / "badges" / "frontend-coverage.json").read_text(encoding="utf-8")
    )

    assert python_badge["label"] == "Python"
    assert python_badge["message"] == "96.2%"
    assert frontend_badge["label"] == "Frontend"
    assert frontend_badge["message"] == "97.4%"
