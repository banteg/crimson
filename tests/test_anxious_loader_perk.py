from __future__ import annotations

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_anxious_loader_reduces_reload_timer_on_fire_press() -> None:
    state = GameplayState()

    base_player = PlayerState(index=0, pos=Vec2(), weapon_id=1)
    base_player.reload_active = True
    base_player.reload_timer_max = 1.0
    base_player.reload_timer = 1.0

    perk_player = PlayerState(index=0, pos=Vec2(), weapon_id=1)
    perk_player.perk_counts[int(PerkId.ANXIOUS_LOADER)] = 1
    perk_player.reload_active = True
    perk_player.reload_timer_max = 1.0
    perk_player.reload_timer = 1.0

    input_state = PlayerInput(fire_pressed=True)
    player_update(base_player, input_state, dt=0.1, state=state)
    player_update(perk_player, input_state, dt=0.1, state=state)

    assert_float_close(base_player.reload_timer, 0.9)
    assert_float_close(perk_player.reload_timer, 0.85)
