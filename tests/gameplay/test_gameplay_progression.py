from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import survival_check_level_up
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.factories import make_step_runtime, world_with_creature


def test_survival_level_up_advances_one_threshold_per_tick() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), level=1, experience=5000)

    survival_check_level_up(state, player)
    survival_check_level_up(state, player)

    assert player.level == 3
    assert state.perk_selection.pending_count == 2
    assert state.perk_selection.choices_dirty is True
    assert [request.sfx_id for request in state.sfx_queue] == [SfxId.UI_LEVELUP, SfxId.UI_LEVELUP]


def test_kill_experience_rounds_the_exact_int_plus_reward_once() -> None:
    player = PlayerState(index=0, pos=Vec2(), experience=(1 << 24) + 1)
    world = world_with_creature(CreatureState(active=True, hp=0.0, reward_value=0.5), players=[player])
    world.state.bonuses.double_experience = 5.0
    world.state.bonus_spawn_guard = True
    step_runtime = make_step_runtime(world)

    step_runtime.handle_creature_death(0)

    # `fild` keeps 2^24 + 1 exact; the PC24 `fadd` rounds 2^24 + 1.5 up to 2^24 + 2,
    # and the Double Experience repeat lands on 2^24 + 2 again.
    assert player.experience == (1 << 24) + 2
    assert step_runtime.deaths[0].xp_awarded == 1
