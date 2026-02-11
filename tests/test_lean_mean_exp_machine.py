from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects


def test_perks_update_effects_lean_mean_exp_machine_ticks_xp_without_double_xp() -> None:
    state = GameplayState()
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    player.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player], 0.2)
    assert player.experience == 0

    perks_update_effects(state, [player], 0.1)
    assert player.experience == 20
    assert math.isclose(state.lean_mean_exp_timer, 0.25, abs_tol=1e-9)


def test_lean_mean_exp_machine_tick_awards_only_player0_in_multiplayer() -> None:
    state = GameplayState()
    state.lean_mean_exp_timer = 0.05

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0))
    player0.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2
    player1.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player0, player1], 0.1)

    assert player0.experience == 20
    assert player1.experience == 0
