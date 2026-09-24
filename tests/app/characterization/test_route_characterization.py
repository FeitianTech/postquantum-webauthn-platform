"""The ceremony and decoder routes answer exactly what they answered before.

Each scenario in ``scenarios.py`` runs against a fresh app in the pinned
environment of ``harness.py``, and its record must equal ``golden/routes/<name>.json``
byte for byte. The goldens were recorded on the tree before Phase 18 changed
anything; ``CHARACTERIZATION_WRITE=1`` rewrites them after an intended change.
"""
from __future__ import annotations

import pytest

from . import harness
from .scenarios import SCENARIOS


@pytest.fixture
def environment(monkeypatch, tmp_path):
    env = harness.Environment(monkeypatch, tmp_path)
    yield env
    env.close()


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_route_answers_match_their_golden_record(name, environment):
    harness.check_golden(f"routes/{name}.json", harness.run(name, environment, SCENARIOS[name]))
