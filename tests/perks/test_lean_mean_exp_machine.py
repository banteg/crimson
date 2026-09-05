from __future__ import annotations

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueue
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_perks_update_effects_lean_mean_exp_machine_ticks_xp_without_double_xp() -> None:
    state = GameplayState()
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    player.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player], 0.2, creatures=CreaturePool().entries, fx_queue=FxQueue())
    assert player.experience == 0

    perks_update_effects(state, [player], 0.1, creatures=CreaturePool().entries, fx_queue=FxQueue())
    assert player.experience == 20
    assert_float_close(state.lean_mean_exp_timer, 0.25)


def test_lean_mean_exp_machine_tick_awards_only_player0_in_multiplayer() -> None:
    state = GameplayState()
    state.lean_mean_exp_timer = 0.05

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0))
    player0.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2
    player1.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 2

    perks_update_effects(state, [player0, player1], 0.1, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert player0.experience == 20
    assert player1.experience == 0


def test_perk_effect_timers_keep_native_36hz_cadence() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(10.0, 20.0),
        shield_timer=0.25,
        fire_bullets_timer=0.25,
        speed_bonus_timer=0.25,
    )
    player.perk_counts[int(PerkId.LEAN_MEAN_EXP_MACHINE)] = 1

    for _ in range(9):
        perks_update_effects(state, [player], 1.0 / 36.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert state.lean_mean_exp_timer == 1.1175870895385742e-08
    assert player.shield_timer == 1.1175870895385742e-08
    assert player.fire_bullets_timer == 1.1175870895385742e-08
    assert player.speed_bonus_timer == 1.1175870895385742e-08
    assert player.experience == 0

    perks_update_effects(state, [player], 1.0 / 36.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert state.lean_mean_exp_timer == 0.25
    assert player.experience == 10
