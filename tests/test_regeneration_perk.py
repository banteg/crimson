from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_perks_update_effects_regeneration_heals_when_rng_allows() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)  # rand & 1 == 1

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.2, abs_tol=1e-9)


def test_perks_update_effects_regeneration_skips_when_rng_blocks() -> None:
    state = GameplayState()
    state.rng = _FixedRng(0)  # rand & 1 == 0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.0, abs_tol=1e-9)


def test_perks_update_effects_greater_regeneration_doubles_heal_by_default() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)  # rand & 1 == 1
    state.preserve_bugs = False

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1
    player.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.4, abs_tol=1e-9)


def test_perks_update_effects_greater_regeneration_keeps_noop_with_preserve_bugs() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)  # rand & 1 == 1
    state.preserve_bugs = True

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1
    player.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert math.isclose(player.health, 90.2, abs_tol=1e-9)
