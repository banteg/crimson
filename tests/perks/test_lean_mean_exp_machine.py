from __future__ import annotations

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueue
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_lean_mean_exp_machine_tick_awards_only_player0_in_multiplayer() -> None:
    state = GameplayState()
    state.lean_mean_exp_timer = 0.05

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0))
    state.perks[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player0, player1], 0.1, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert player0.experience == 20
    assert player1.experience == 0
