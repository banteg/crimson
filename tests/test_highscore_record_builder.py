from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.modes.components.highscore_record_builder import (
    build_highscore_record_for_game_over,
    clamp_shots,
    shots_from_state,
)


def test_clamp_shots_clamps_hit_and_nonnegative() -> None:
    assert clamp_shots(-5, 10) == (0, 0)
    assert clamp_shots(5, -1) == (5, 0)
    assert clamp_shots(5, 10) == (5, 5)


def test_shots_from_state_handles_out_of_bounds_player() -> None:
    state = GameplayState()
    assert shots_from_state(state, player_index=99) == (0, 0)


def test_build_highscore_record_for_game_over_uses_weapon_stats_and_shots() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    player.experience = 1234
    player.weapon_id = 1

    state.weapon_shots_fired[0][2] = 10
    state.shots_fired[0] = 20
    state.shots_hit[0] = 15

    record = build_highscore_record_for_game_over(
        state=state,
        player=player,
        survival_elapsed_ms=5000,
        creature_kill_count=7,
        game_mode_id=1,
    )

    assert record.score_xp == 1234
    assert record.survival_elapsed_ms == 5000
    assert record.creature_kill_count == 7
    assert record.most_used_weapon_id == 2
    assert record.shots_fired == 20
    assert record.shots_hit == 15
    assert record.game_mode_id == 1


def test_build_highscore_record_for_game_over_can_skip_clamp() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())

    record = build_highscore_record_for_game_over(
        state=state,
        player=player,
        survival_elapsed_ms=0,
        creature_kill_count=0,
        game_mode_id=4,
        shots_fired=3,
        shots_hit=5,
        clamp_shots_hit=False,
    )

    assert record.shots_fired == 3
    assert record.shots_hit == 5

