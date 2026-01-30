from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update
from crimson.perks import PerkId


def test_long_distance_runner_ramps_speed_above_base_cap() -> None:
    dt = 0.1
    steps = 12  # reaches 0.4s warmup + 0.8s ramp

    input_state = PlayerInput(move_x=1.0, move_y=0.0, aim_x=101.0, aim_y=100.0)

    base_state = GameplayState()
    base_player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)
    base_start_x = base_player.pos_x
    for _ in range(steps):
        player_update(base_player, input_state, dt, base_state)

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)
    perk_player.perk_counts[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    perk_start_x = perk_player.pos_x
    for _ in range(steps):
        player_update(perk_player, input_state, dt, perk_state)

    assert base_player.pos_x == pytest.approx(base_start_x + 240.0 * dt * steps)
    assert perk_player.long_distance_runner_timer == pytest.approx(1.2)
    assert perk_player.pos_x == pytest.approx(perk_start_x + 331.2)
    assert perk_player.pos_x > base_player.pos_x

    player_update(perk_player, PlayerInput(aim_x=perk_player.pos_x + 1.0, aim_y=perk_player.pos_y), dt, perk_state)
    assert perk_player.long_distance_runner_timer == pytest.approx(0.0)
