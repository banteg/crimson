from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects


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
