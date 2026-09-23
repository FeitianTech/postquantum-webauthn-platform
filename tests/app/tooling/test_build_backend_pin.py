"""The vendored fido2 package's build backend is pinned to one exact release.

``uv.lock`` records no build requirements, so a range here lets a new backend
release break a build of an unchanged commit. The pin is bumped by
``.github/workflows/update-build-backend.yml``, which tests the new release first.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT_PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"
_EXACT_PIN = re.compile(r"^poetry-core==\d+\.\d+\.\d+$")


def test_build_backend_is_pinned_to_one_exact_poetry_core_release():
    build_system = tomllib.loads(_ROOT_PYPROJECT.read_text(encoding="utf-8"))["build-system"]

    assert build_system["build-backend"] == "poetry.core.masonry.api"
    assert len(build_system["requires"]) == 1
    assert _EXACT_PIN.match(build_system["requires"][0]), build_system["requires"]
