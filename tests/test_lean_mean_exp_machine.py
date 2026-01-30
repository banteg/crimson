from __future__ import annotations

import math

from crimson.gameplay import GameplayState, PlayerState, perks_update_effects
from crimson.perks import PerkId


def test_perks_update_effects_lean_mean_exp_machine_ticks_xp_without_double_xp() -> None:
    state = GameplayState()
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos_x=10.0, pos_y=20.0)
    player.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player], 0.2)
    assert player.experience == 0

    perks_update_effects(state, [player], 0.1)
    assert player.experience == 20
    assert math.isclose(state.lean_mean_exp_timer, 0.25, abs_tol=1e-9)

