"""canonical.check: what checking a map keeps alive while it walks into its keys."""
from __future__ import annotations

from server.app.decoder.decode import canonical
from tests.app.decoder.key_chains import key_chain, traced_peak


def test_a_key_nested_in_keys_is_not_held_once_per_level():
    # With every level's key identities and bytes held through the walk, 30 levels cost about 30 times one.
    (shallow_node, shallow_data), (deep_node, deep_data) = key_chain(200, 1), key_chain(200, 30)

    shallow = traced_peak(lambda: canonical.check(shallow_node, shallow_data))
    deep = traced_peak(lambda: canonical.check(deep_node, deep_data))

    assert deep < 5 * shallow
