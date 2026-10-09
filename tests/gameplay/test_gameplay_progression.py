from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreatureState
from crimson.game_modes import GameMode
from crimson.gameplay import survival_check_level_up
from crimson.perks import PerkId
from crimson.perks.selection import PerkPick, perk_selection_open_choices, perk_selection_pick
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, world_with_creature


@pytest.mark.parametrize("reopen_menu", [False, True])
def test_survival_level_up_preserves_waiting_perk_offer(reopen_menu: bool) -> None:
    world = make_world(seed=85)
    state = world.state
    player = world.players[0]
    player.health = 25.0
    player.experience = 5000
    offered = [PerkId.FASTLOADER, PerkId.NINJA, PerkId.DEATH_CLOCK]
    state.perk_selection = PerkSelectionState(
        pending_count=1,
        choices=offered.copy(),
        choices_dirty=False,
    )
    rng_before = state.rng.state

    survival_check_level_up(state, player)
    survival_check_level_up(state, player)

    assert player.level == 3
    assert state.perk_selection.pending_count == 3
    if reopen_menu:
        assert perk_selection_open_choices(state, world.players, game_mode=GameMode.SURVIVAL) == offered

    picked = perk_selection_pick(state, world.players, 2, game_mode=GameMode.SURVIVAL, dt=0.0, creatures=[])

    # The pick comes from the offer that waited through the level-ups.
    assert picked == PerkPick(offered=tuple(offered), chosen=2)
    assert picked.perk_id == PerkId.DEATH_CLOCK
    assert player.health == 100.0
    assert state.rng.state == rng_before
    assert state.perk_selection.pending_count == 2
    assert state.perk_selection.choices_dirty is True


def test_kill_experience_rounds_the_exact_int_plus_reward_once() -> None:
    player = PlayerState(index=0, pos=Vec2(), experience=(1 << 24) + 1)
    world = world_with_creature(CreatureState(active=True, hp=0.0, reward_value=0.5), players=[player])
    world.state.bonuses.double_experience = 5.0
    world.state.scripted_burst_active = True
    step_runtime = make_step_runtime(world)

    world.creatures.handle_death(step_runtime, 0)

    # `fild` keeps 2^24 + 1 exact; the PC24 `fadd` rounds 2^24 + 1.5 up to 2^24 + 2,
    # and the Double Experience repeat lands on 2^24 + 2 again.
    assert player.experience == (1 << 24) + 2
    assert step_runtime.deaths[0].xp_awarded == 1
