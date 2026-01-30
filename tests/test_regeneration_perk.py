from __future__ import annotations

import math

from crimson.gameplay import GameplayState, PlayerState, perks_update_effects
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_perks_update_effects_regeneration_heals_when_rng_allows() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)  # rand & 1 == 1

    player = PlayerState(index=0, pos_x=10.0, pos_y=20.0, health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.2, abs_tol=1e-9)


def test_perks_update_effects_regeneration_skips_when_rng_blocks() -> None:
    state = GameplayState()
    state.rng = _FixedRng(0)  # rand & 1 == 0

    player = PlayerState(index=0, pos_x=10.0, pos_y=20.0, health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.0, abs_tol=1e-9)

