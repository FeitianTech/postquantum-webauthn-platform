"""Unit tests for the single-use challenge registry itself.

The end-to-end replay tests live next to each flow; these pin down the two
rules the registry relies on -- consumption and freshness -- in isolation.
"""
from __future__ import annotations

import time

import pytest

from server.app import challenge_registry as registry_module
from server.app.challenge_registry import (
    CHALLENGE_EXPIRED,
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    InMemoryChallengeRegistry,
    consume_ceremony_state,
    stamp_ceremony_state,
)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def fresh_registry(monkeypatch):
    registry = InMemoryChallengeRegistry()
    monkeypatch.setattr(registry_module, "_registry", registry)
    return registry


def test_a_challenge_can_only_be_consumed_once():
    registry = InMemoryChallengeRegistry(ttl_seconds=60)

    assert registry.consume("abc") is True
    assert registry.consume("abc") is False
    assert registry.consume("abc") is False
    # A different challenge is unaffected.
    assert registry.consume("def") is True


def test_records_are_evicted_only_after_their_ttl():
    clock = _FakeClock()
    registry = InMemoryChallengeRegistry(ttl_seconds=60, clock=clock)

    assert registry.consume("abc") is True
    clock.now += 59
    assert registry.consume("abc") is False
    assert len(registry) == 1

    clock.now += 2
    assert len(registry) == 0


def test_default_retention_outlives_the_acceptance_window():
    registry = InMemoryChallengeRegistry()
    assert registry._ttl >= registry_module.challenge_ttl_seconds()


def test_stamped_state_is_fresh_once_then_replayed(fresh_registry):
    state = stamp_ceremony_state({"challenge": "Y2hhbGxlbmdl"})

    assert consume_ceremony_state(state) == CHALLENGE_FRESH
    assert consume_ceremony_state(dict(state)) == CHALLENGE_REPLAYED


def test_state_without_issued_at_is_expired_and_still_consumed(fresh_registry):
    state = {"challenge": "bm8tc3RhbXA"}

    assert consume_ceremony_state(state) == CHALLENGE_EXPIRED
    # Even the expired attempt burnt the challenge.
    stamped = stamp_ceremony_state(dict(state))
    assert consume_ceremony_state(stamped) == CHALLENGE_REPLAYED


def test_state_older_than_ttl_is_expired(fresh_registry, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_CHALLENGE_TTL_SECONDS", "30")
    state = {"challenge": "b2xk", "issued_at": time.time() - 31}

    assert consume_ceremony_state(state) == CHALLENGE_EXPIRED


@pytest.mark.parametrize(
    "state",
    [None, "not-a-mapping", {}, {"challenge": ""}, {"challenge": 7, "issued_at": time.time()}],
)
def test_malformed_state_is_never_fresh(fresh_registry, state):
    assert consume_ceremony_state(state) == CHALLENGE_EXPIRED


def test_boolean_issued_at_is_not_a_timestamp(fresh_registry):
    assert consume_ceremony_state({"challenge": "Ym9vbA", "issued_at": True}) == CHALLENGE_EXPIRED
